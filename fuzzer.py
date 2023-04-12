import log
import os
import sys
import time 
from coverage import parse_coverage, write_drcov_file

class fuzzer():

    def __init__(self, project, pid, target_module, target_function, frida_script = 'agent.js'):
        self.project                = project
        self.pid                    = pid
        self.target_module          = target_module
        self.target_function        = target_function
        self.frida_script           = os.path.join(os.path.dirname(__file__), frida_script)
        self.corpus                 = None
        self.accumulated_coverage   = set()
        self.total_executions       = 0
        self.start_time             = None
        self.payload_filter_function= None
        self.max_payload_size       = 0
        self.frida_port             = 27042 

        self.project_debug          = self.project + "/debug"
        self.project_crash          = self.project + "/crash"
        self.project_corpus         = self.project + "/corpus"
        self.coverage_dir           = self.project + time.strftime("/%Y%m%d_%H%M%S_coverage")

        # Creating project
        
        if os.path.exists(self.project):
            log.warn("Project '%s' already exists!" % self.project)
            sys.exit(-1)

        log.info("Creating project '%s'!" % self.project)

        os.mkdir(self.project)
        
        if not os.path.exists(self.project_debug):
            os.mkdir(self.project_debug)

        if not os.path.exists(self.project_crash):
            os.mkdir(self.project_crash)

        if not os.path.exists(self.project_corpus):
            os.mkdir(self.project_corpus)
        
        if not os.path.exists(self.coverage_dir):
            os.mkdir(self.coverage_dir)

        log.info("Loading script: %s" % self.frida_script)
        script_code = open(self.frida_script, "r").read()

        log.info("Attaching script at target")
        self.pid.attach(script_code)

        # Creating Corpus if not exists
        
        log.info("Initializing Corpus...")

        self.accumulated_coverage = set()

        corpus = [self.corpus_dir + "/" + x for x in os.listdir(self.corpus_dir)]
        corpus.sort()

        if len(corpus) == 0:
            with open("1","w+") as f:
                f.write("AAAA")

        for infile in corpus:
            fuzz_pkt = open(infile, "rb").read()
            coverage_last = None
            for i in range(5):
                t = time.strftime("%Y-%m-%d %H:%M:%S")
                log.update(t + " [iteration=%d] %s" % (i, infile))

                coverage = self.get_coverage_of_payload(fuzz_pkt, timeout=1)
                if coverage == None or len(coverage) == 0:
                    log.warn("No coverage was returned! you might want to delete %s from corpus if it happens more often" % infile)

                if coverage_last != None and coverage_last != coverage:
                    log.warn(t + " [iteration=%d] Inconsistent coverage for %s!" % (i, infile))

                coverage_last = coverage
                
                # Accumulate coverage:
                self.accumulated_coverage = self.accumulated_coverage.union(coverage_last)

            write_drcov_file(self.target_module, coverage_last,
                                     self.coverage_dir + "/" + infile.split("/")[-1])

        log.finish_update("Using %d input files which cover a total of %d basic blocks!" % (
                         len(corpus), len(self.accumulated_coverage)))
        self.corpus = corpus

    def fuzz(self, fuzzer):
        if fuzzer.buildCorpus():
            log.debug("Corpus: " + str(fuzzer.corpus))
            fuzzer.fuzzerLoop()
    
    def set_maximum_payload(self, payload_size):
        self.max_payload_size = payload_size

    def set_frida_port(self, port):
        self.frida_port = port

    def get_coverage_of_payload(self, payload, timeout=0.04, retry=0):

        payload = self.runPayloadFilterFunction(payload)
        if payload == None:
            return set()

        cov = None
        cnt = 0
        while cnt <= retry:
            # Clear coverage info in all targets:
            for target in self.targets:
                target.frida_script.exports.clearcoverage()

            # Send payload
            if self.project.fuzz_in_process:
                self.sendFuzzPayloadInProcess(payload)
            else:
                self.sendFuzzPayload(payload)

            # Wait for timeout seconds for any of the stalkers to get attached
            target, stalker_attached, stalker_finished = self.waitForCoverage(timeout)

            if target != None:
                # Found a target that has attached their stalker. Wait for the stalker
                # to finish and then extract the coverage.
                # Wait for 1 second <- maybe this should be adjusted / configurable ?
                start = time.time()
                while not stalker_finished and (time.time()-start) < 1:
                    stalker_attached, stalker_finished = target.frida_script.exports.checkstalker()

                if not stalker_finished:
                    log.info("getCoverageOfPayload: Stalker did not finish after 1 second!")
                    break

                cov = target.frida_script.exports.getcoverage()
                if cov != None and len(cov) > 0:
                    break

            else:
                # None of the targets' function was hit. next try..
                cnt += 1

        if cov == None or len(cov) == 0:
            log.debug("getCoverageOfPayload: got nothing!")
            return set()

        return parse_coverage(cov, self.active_target.watched_modules)