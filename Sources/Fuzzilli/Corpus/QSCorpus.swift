import Foundation
import libafl
    
/// Corpus for mutation-based fuzzing.
public class QSCorpus: ComponentBase, Collection, Corpus {
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

    /// The underlying LibAFL object.
    private var libaflObject: LibAflObject

    public init(minSize: Int, maxSize: Int, minMutationsPerSample: Int, storagepath: String) {
    // The corpus must never be empty. Other components, such as the ProgramBuilder, rely on this.
    assert(minSize >= 1)
    assert(maxSize >= minSize)
    self.minSize = minSize
    self.minMutationsPerSample = minMutationsPerSample

    self.programs = RingBuffer(maxSize: maxSize)
    self.ages = RingBuffer(maxSize: maxSize)

    // Create the shared memory ID for the LibAFL object.
    #if os(Windows)
    let shmID = "shm_id_\(GetCurrentProcessId())_0"
    #else
    let shmID = "shm_id_\(getpid())_0"
    #endif

    // Determine the corpus directory based on whether storagepath is empty.
    let corpusDir: String
    if storagepath.isEmpty {
        corpusDir = "pcorpus"
    } else {
        corpusDir = "\(storagepath)/pcorpus"
    }

    // Initialize the LibAFL object with the determined corpus directory and shared memory ID.
    self.libaflObject = LibAflObject(corpusDir: corpusDir, shmemKey: shmID, schedulerType: 2)
    super.init(name: "Corpus")
    }


    override func initialize() {
        // Schedule a timer to perform cleanup regularly, but only if we're not running as static corpus.
        if !fuzzer.config.staticCorpus {
            fuzzer.timers.scheduleTask(every: 30 * Minutes, cleanup)
        }
    }

    public var size: Int {
        return Int(libaflObject.count())
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
            ages.append(0)
            do {
                try libaflObject.addInput(inputData: program.asProtobuf().serializedData())
            } catch {
                print("LibAFL Corpus add input failed")
                exit(-1)
            }
            totalEntryCounter += 1
        }
    }

    /// Returns a random program from this corpus for use in splicing to another program.
    public func randomElementForSplicing() -> Program {
        do {
            let bytes = libaflObject.suggestNextInput()
            let data = try Data(bytes)
            let proto = try Fuzzilli_Protobuf_Program(serializedData: data)
            let program = try Program(from: proto)
            return program
        } catch {
            print("Random element splicing function failed")
            exit(-1)
        }
    }

    /// Returns a random program from this corpus and increases its age by one.
    public func randomElementForMutating() -> Program {
        do {
            let bytes = libaflObject.suggestNextInput()
            let data = try Data(bytes)
            let proto = try Fuzzilli_Protobuf_Program(serializedData: data)
            let program = try Program(from: proto)
            return program
        } catch {
            print("Random element mutating function failed")
            exit(-1)
        }
    }

    public func allPrograms() -> [Program] {
        return Array(programs)
    }

    public func allFzilPrograms() -> [Program] {
        let firstIndex = libaflObject.firstIndex()
        let lastIndex = libaflObject.lastIndex()
        var allPrograms = [Program]()
        
        assert(firstIndex <= lastIndex, "First index is greater than last index")
        
        for i in firstIndex...lastIndex {
            do {
                let bytes = libaflObject.getElement(id: UInt64(i))
                let data = try Data(bytes)
                let proto = try Fuzzilli_Protobuf_Program(serializedData: data)
                let program = try Program(from: proto)
                allPrograms.append(program)
            } catch {
                print("Failed to fetch program at index \(i)")
                exit(-1)
            }
        }
        
        return allPrograms
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
        return Int(libaflObject.firstIndex())
    }

    public var endIndex: Int {
        return Int(libaflObject.lastIndex())
    }

    public subscript(index: Int) -> Program {  
        do {
            let bytes = libaflObject.getElement(id: UInt64(index))
            let data = try Data(bytes)
            let proto = try Fuzzilli_Protobuf_Program(serializedData: data)
            let program = try Program(from: proto)
            return program
        } catch {
            print("Subscript function failed")
            exit(-1)
        }
    }

    public func index(after i: Int) -> Int {
        return i + 1
    }
}
