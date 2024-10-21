// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import libpc

let filteredFunctionsForCompiler = [
    "assert*",
    "print*",
    "enterFunc",
    "startTest"
]

/// Corpus for mutation-based fuzzing.
///
/// The corpus contains FuzzIL programs that can be used as input for mutations.
/// Any newly found interesting program is added to the corpus.
/// Programs are evicted from the copus for two reasons:
///
///  - if the corpus grows too large (larger than maxCorpusSize), in which
///    case the oldest programs are removed.
///  - if a program has been mutated often enough (at least
///    minMutationsPerSample times).
///
/// However, once reached, the corpus will never shrink below minCorpusSize again.
/// Further, once initialized, the corpus is guaranteed to always contain at least one program.
public class ParthCorpus: ComponentBase, Collection, Corpus {
    /// The minimum number of samples that should be kept in the corpus.
    private let minSize: Int

    /// The minimum number of times that a sample from the corpus was used
    /// for mutation before it can be discarded from the active set.
    private let minMutationsPerSample: Int

    /// The current set of interesting programs used for mutations.
    private var programs: RingBuffer<Program>
    private var ages: RingBuffer<Int>

    /// Counts the total number of entries in the corpus.
    private var totalEntryCounter = 0
    private var pcorpus : FzilOnDiskCorpusBytes

    public init(minSize: Int, maxSize: Int, minMutationsPerSample: Int) {
        // The corpus must never be empty. Other components, such as the ProgramBuilder, rely on this
        assert(minSize >= 1)
        assert(maxSize >= minSize)
        self.minSize = minSize
        self.minMutationsPerSample = minMutationsPerSample

        self.programs = RingBuffer(maxSize: maxSize)
        self.ages = RingBuffer(maxSize: maxSize)

        self.pcorpus = FzilOnDiskCorpusBytes()

        super.init(name: "Corpus")
    }

    override func initialize() {
        // Schedule a timer to perform cleanup regularly, but only if we're not running as static corpus.
        if !fuzzer.config.staticCorpus {
            fuzzer.timers.scheduleTask(every: 30 * Minutes, cleanup)
        }
    }

    public var size: Int {
        return Int(pcorpus.count())
    }

    public var isEmpty: Bool {
        return size == 0
    }

    public var supportsFastStateSynchronization: Bool {
        return false
    }

    public func add(_ program: Program, _ : ProgramAspects) {
        addInternal(program)
    }


    public func addInternal(_ program: Program) {
        if program.size > 0 {
            prepareProgramForInclusion(program, index: totalEntryCounter)
            // programs.append(program)
            ages.append(0)
            do{
                try pcorpus.addInput(input: program.asProtobuf().serializedData())
                //Testing print for a corpus element
                // if totalEntryCounter == 2
                // {
                //     let corpusId: UInt64 = 1  // Replace with the corpus ID you want to retrieve
                //     let bytes = pcorpus.getElement(corpusId: corpusId)
                //     let data = Data(bytes)
                //     let proto = try Fuzzilli_Protobuf_Program(serializedData: data)
                //     dump(proto, maxDepth: 3)
                // }
            }
            catch{
                print("Fzil Corpus add input failed")
                exit(-1)
            }
            totalEntryCounter += 1
        }
    }

    /// Returns a random program from this corpus for use in splicing to another program
    public func randomElementForSplicing() -> Program {
        do{
            let bytes = pcorpus.getRandomElement() 
            let data =  try Data(bytes)
            let proto = try Fuzzilli_Protobuf_Program(serializedData: data)
            let program = try Program(from: proto)
            return program
        }
        catch{
            print("random element splicing function failed")
            exit(-1)
        }
        
        // let idx = Int.random(in: 0..<programs.count)
        // let program = programs[idx]
        // assert(!program.isEmpty)
        // return program
    }

    /// Returns a random program from this corpus and increases its age by one.
    public func randomElementForMutating() -> Program {
        do{
            let bytes = pcorpus.getRandomElement() 
            let data =  try Data(bytes)
            let proto = try Fuzzilli_Protobuf_Program(serializedData: data)
            let program = try Program(from: proto)
            return program
        }
        catch{
            print("random element mutating function failed")
            exit(-1)
        }

        // let idx = Int.random(in: 0..<programs.count)    
        // ages[idx] += 1
        // let program = programs[idx]
        // assert(!program.isEmpty)
        // return program
    }

    public func allPrograms() -> [Program] {
        return Array(programs)
    }

    public func exportState() throws -> Data {
        let programs = allFzilPrograms()
        let res = try encodeProtobufCorpus(programs)
        logger.info("Successfully serialized \(programs.count) programs")
        return res
    }

    public func importState(_ buffer: Data) throws {
        let newPrograms = try decodeProtobufCorpus(buffer)
        programs.removeAll()
        ages.removeAll()
        newPrograms.forEach(addInternal)
    }

    private func cleanup() {
        assert(!fuzzer.config.staticCorpus)
        var newPrograms = RingBuffer<Program>(maxSize: programs.maxSize)
        var newAges = RingBuffer<Int>(maxSize: ages.maxSize)

        for i in 0..<programs.count {
            let remaining = programs.count - i
            if ages[i] < minMutationsPerSample || remaining <= (minSize - newPrograms.count) {
                newPrograms.append(programs[i])
                newAges.append(ages[i])
            }
        }

        logger.info("Corpus cleanup finished: \(self.programs.count) -> \(newPrograms.count)")
        programs = newPrograms
        ages = newAges
    }

    public var startIndex: Int {    
        return Int(pcorpus.firstIndex())
    }

    public var endIndex: Int {
        return Int(pcorpus.lastIndex())
    }

    public subscript(index: Int) -> Program {  
        do{
            let bytes = pcorpus.getElement(corpusId: UInt64(index)) 
            let data =  try Data(bytes)
            let proto = try Fuzzilli_Protobuf_Program(serializedData: data)
            let program = try Program(from: proto)
            return program
        }
        catch{
            print("subscript function failed")
            exit(-1)
        }
    }

    public func index(after i: Int) -> Int {
        return i + 1
    }

    public func allFzilPrograms() -> [Program] {
        let first_index = pcorpus.firstIndex()
        let last_index = pcorpus.lastIndex()
        var all_programs = [Program]()
        assert (first_index<=last_index, "First index is bigger than last index")

        for i in first_index...last_index{
            do{
                let bytes = pcorpus.getElement(corpusId: UInt64(i)) 
                let data =  try Data(bytes)
                let proto = try Fuzzilli_Protobuf_Program(serializedData: data)
                let program = try Program(from: proto)
                all_programs.append(program)
            }
            catch{
                print("all fzil programs function failed")
                exit(-1)
            }
        }
        return all_programs
    }
}
