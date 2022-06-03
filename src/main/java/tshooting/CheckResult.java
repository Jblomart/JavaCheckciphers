/**
* Tshooting tools.
* 
* <P>Tools for tshooting...
*  
@author Jerome Blomart
@version 0.1
*/
package tshooting;

import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
* Object to store check results.
* 
* <P> Has a semaphore to lock the result object until completion.
*  
@author Jerome Blomart
@version 0.1
*/
public class CheckResult {
    private static final Integer MAX_RUNS = 1;
    private final Semaphore available = new Semaphore(MAX_RUNS, Boolean.TRUE);

    private String outputstr;
    private Boolean summary;
    private Boolean verbose;
    private Boolean fatalException;
    private Integer timeout;

    /**
     * Consturctor 
     * 
     * @param summary <code>Boolean</code> Do outputs need a summary.
     * @param verbose <code>Boolean</code> Are outputs verbose.
     * @param timeout <code>Doolean</code> Timeout for Semaphore acquire and wait.
     */
    public CheckResult(Boolean summary, Boolean verbose, Integer timeout) {
        this.outputstr = "";
        this.summary = summary;
        this.verbose = verbose;
        this.timeout = timeout;
        this.fatalException = Boolean.FALSE;
    }

    /**
     * Append string to output
     * 
     * @param content <code>String<code> Text to append to outputs.
     */
    public void appendOutputStr(String content) {
        if (this.outputstr.length() > 0) { this.outputstr += "\n"; }
        this.outputstr += content;
    }

    /**
     * Getter for Semaphore 
     * 
     * @return
     */
    public Semaphore getAvailable() {
        return this.available;
    }

    /**
     * Getter for Summary
     * 
     * @return
     */
    public Boolean getSummary() {
        return this.summary;
    }

    /**
     * Getter for Verbose
     * 
     * @return 
     */
    public Boolean getVerbose() {
        return this.verbose;
    }

    /**
     * Getter for outputs
     * 
     * @return
     */
    public String getOutput() {
        return this.outputstr;
    }

    /**
     * Setter for fatal exception state
     * 
     * <P> When a fatal exception happenned during processing.
     * 
     */
    public void setFatalException() {
        this.fatalException = Boolean.TRUE;
    }

    /**
     * Getter for fatal exception state
     * 
     * <P> To check if a fatal exception hapenned during processing.
     * 
     * @return <code>Boolean</code> fatalException flag.
     */
    public Boolean getFatalException() {
        return this.fatalException;
    }

    /**
     * Acquire Semaphore with timeout
     * 
     * @throws InterruptedException
     */
    public void acquire() throws InterruptedException { 
        this.available.tryAcquire(timeout,TimeUnit.MILLISECONDS);
    }

    /**
     * Release Semaphore
     */
    public void release() {
        this.available.release();
    }

    /**
     * Wait for Semaphore with timeout
     * 
     * @throws InterruptedException
     */
    public void semaphoreWait() throws InterruptedException {
        this.available.wait(timeout);
    }
}