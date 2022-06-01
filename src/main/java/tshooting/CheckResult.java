package tshooting;

import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

public class CheckResult {
    private static final Integer MAX_RUNS = 1;
    private final Semaphore available = new Semaphore(MAX_RUNS, Boolean.TRUE);

    private String outputstr;
    private Boolean summary;
    private Boolean verbose;
    private Boolean fatalException;
    private Integer timeout;

    public CheckResult(Boolean summary, Boolean verbose, Integer timeout) {
        this.outputstr = "";
        this.summary = summary;
        this.verbose = verbose;
        this.timeout = timeout;
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
        this.available.tryAcquire(timeout,TimeUnit.MILLISECONDS);
    }

    public void release() {
        this.available.release();
    }

    public void semaphoreWait() throws InterruptedException {
        this.available.wait(timeout);
    }
}