package tshooting;

import java.util.concurrent.Semaphore;

public class CheckResult {
    private static final Integer MAX_RUNS = 1;
    private final Semaphore available = new Semaphore(MAX_RUNS, Boolean.TRUE);

    private String outputstr;
    private Boolean summary;
    private Boolean verbose;
    private Boolean fatalException;

    public CheckResult(Boolean summary, Boolean verbose) {
        this.outputstr = "";
        this.summary = summary;
        this.verbose = verbose;
        this.fatalException = Boolean.FALSE;
    }

    public void appendOutputStr(String content) {
        if (this.outputstr.length() > 0) { this.outputstr += "\n"; }
        this.outputstr += content;
    }

    public Semaphore getAvailable() {
        return this.available;
    }

    public Boolean getSummary() {
        return this.summary;
    }

    public Boolean getVerbose() {
        return this.verbose;
    }

    public String getOutput() {
        return this.outputstr;
    }

    public void setFatalException() {
        this.fatalException = Boolean.TRUE;
    }

    public Boolean getFatalException() {
        return this.fatalException;
    }

    public void acquire() throws InterruptedException { 
        this.available.acquire();
    }

    public void release() {
        this.available.release();
    }

    public void semaphoreWait() throws InterruptedException {
        this.available.wait();
    }
}