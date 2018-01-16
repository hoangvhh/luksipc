//
// Created by hoangvh on 15/01/2018.
//

#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>

#include "random.h"
#include "logging.h"
#include "exit.h"
#include "luks.h"
#include "parameters.h"
#include "chunk.h"
#include "utils.h"
#include "exec.h"
#include "globals.h"
#include "shutdown.h"

#include "decrypt.h"

#define REMAINING_BYTES(aconvptr)		(((aconvptr)->endOutOffset) - ((aconvptr)->outOffset))

struct DecryptProcess {
    int readDevFd, writeDevFd;
    uint64_t readDevSize, writeDevSize;
    struct chunk dataBuffer;
//    int usedBufferIndex;
    int resumeFd;
//    char *rawDeviceAlias;
    bool reluksification;
    uint64_t inOffset, outOffset;
    uint64_t endOutOffset;
    char *readDeviceHandle;
    char readDevicePath[60];

    struct {
        double startTime;
        double lastShowTime;
        uint64_t lastOutOffset;
        uint64_t copied;
    } stats;
};

enum copyResult_t {
    COPYRESULT_SUCCESS_FINISHED,
    COPYRESULT_SUCCESS_RESUMABLE,
    COPYRESULT_ERROR_WRITING_RESUME_FILE,
};

bool checkedWrite(int aFd, void *aData, int aLength) {
    ssize_t result = write(aFd, aData, aLength);
    if (result != aLength) {
        logmsg(LLVL_ERROR, "Error while trying to write %d bytes to file with FD #%d: only %ld bytes written: %s\n", aLength, aFd, result, strerror(errno));
        return false;
    }
    return true;
}

bool checkedRead(int aFd, void *aData, int aLength) {
    ssize_t result = read(aFd, aData, aLength);
    if (result != aLength) {
        logmsg(LLVL_ERROR, "Error while trying to read %d bytes from file with FD #%d: only %ld bytes read: %s\n", aLength, aFd, result, strerror(errno));
        return false;
    }
    return true;
}


bool writeResumeFile(struct DecryptProcess *aConvProcess) {
    bool success = true;
    char header[RESUME_FILE_HEADER_MAGIC_LEN];
    memcpy(header, RESUME_FILE_HEADER_MAGIC, RESUME_FILE_HEADER_MAGIC_LEN);
    success = (lseek(aConvProcess->resumeFd, 0, SEEK_SET) != -1) && success;
    success = checkedWrite(aConvProcess->resumeFd, header, sizeof(header)) && success;
    success = checkedWrite(aConvProcess->resumeFd, &aConvProcess->outOffset, sizeof(uint64_t)) && success;
    success = checkedWrite(aConvProcess->resumeFd, &aConvProcess->readDevSize, sizeof(uint64_t)) && success;
    success = checkedWrite(aConvProcess->resumeFd, &aConvProcess->writeDevSize, sizeof(uint64_t)) && success;
    success = checkedWrite(aConvProcess->resumeFd, &aConvProcess->reluksification, sizeof(bool)) && success;
//    success = checkedWrite(aConvProcess->resumeFd, &aConvProcess->dataBuffer[aConvProcess->usedBufferIndex].used, sizeof(uint32_t)) && success;
//    success = checkedWrite(aConvProcess->resumeFd, aConvProcess->dataBuffer[aConvProcess->usedBufferIndex].data, aConvProcess->dataBuffer[aConvProcess->usedBufferIndex].size) && success;
    fsync(aConvProcess->resumeFd);
    logmsg(LLVL_DEBUG, "Wrote resume file: read pointer offset %" PRIu64 " write pointer offset %" PRIu64 ".\n", aConvProcess->inOffset, aConvProcess->outOffset);
    return success;
}

bool readResumeFile(struct conversionParameters const *aParameters, struct DecryptProcess *aConvProcess) {
    bool success = true;
    char header[RESUME_FILE_HEADER_MAGIC_LEN];
    success = (lseek(aConvProcess->resumeFd, 0, SEEK_SET) != -1) && success;
    if (!success) {
        logmsg(LLVL_ERROR, "Seek error while trying to read resume file: %s\n", strerror(errno));
        return false;
    }

    success = checkedRead(aConvProcess->resumeFd, header, sizeof(header)) && success;
    if (!success) {
        logmsg(LLVL_ERROR, "Read error while trying to read resume file header.\n");
        return false;
    }

    if (memcmp(header, RESUME_FILE_HEADER_MAGIC, RESUME_FILE_HEADER_MAGIC_LEN) != 0) {
        logmsg(LLVL_ERROR, "Header magic mismatch in resume file.\n");
        return false;
    }

    uint64_t origReadDevSize, origWriteDevSize;
    bool origReluksification;
    success = checkedRead(aConvProcess->resumeFd, &aConvProcess->outOffset, sizeof(uint64_t)) && success;
    success = checkedRead(aConvProcess->resumeFd, &origReadDevSize, sizeof(uint64_t)) && success;
    success = checkedRead(aConvProcess->resumeFd, &origWriteDevSize, sizeof(uint64_t)) && success;
    success = checkedRead(aConvProcess->resumeFd, &origReluksification, sizeof(bool)) && success;

    if (!success) {
        logmsg(LLVL_ERROR, "Read error while trying to read resume file offset metadata.\n");
        return false;
    }

    if (origReadDevSize != aConvProcess->readDevSize) {
        if (aParameters->safetyChecks) {
            logmsg(LLVL_ERROR, "Resume file used read device of size %" PRIu64 " bytes, but currently read device size is %" PRIu64 " bytes. Refusing to continue in spite of mismatch.\n", origReadDevSize, aConvProcess->readDevSize);
            return false;
        } else {
            logmsg(LLVL_WARN, "Resume file used read device of size %" PRIu64 " bytes, but currently read device size is %" PRIu64 " bytes. Continuing only because safety checks are disabled.\n", origReadDevSize, aConvProcess->readDevSize);
        }
    }
    if (origWriteDevSize != aConvProcess->writeDevSize) {
        if (aParameters->safetyChecks) {
            logmsg(LLVL_ERROR, "Resume file used write device of size %" PRIu64 " bytes, but currently write device size is %" PRIu64 " bytes. Refusing to continue in spite of mismatch.\n", origWriteDevSize, aConvProcess->writeDevSize);
            return false;
        } else {
            logmsg(LLVL_WARN, "Resume file used write device of size %" PRIu64 " bytes, but currently write device size is %" PRIu64 " bytes. Continuing only because safety checks are disabled.\n", origWriteDevSize, aConvProcess->writeDevSize);
        }
    }
    if (origReluksification != aConvProcess->reluksification) {
        if (aParameters->safetyChecks) {
            logmsg(LLVL_ERROR, "Resume file was performing reLUKSification, command line specification indicates you do not want reLUKSification. Refusing to continue in spite of mismatch.\n");
            return false;
        } else {
            logmsg(LLVL_WARN, "Resume file was performing reLUKSification, command line specification indicates you do not want reLUKSification. Continuing only because safety checks are disabled.\n");
        }
    }

    logmsg(LLVL_DEBUG, "Read write pointer offset %" PRIu64 " from resume file.\n", aConvProcess->outOffset);

//    aConvProcess->usedBufferIndex = 0;
//    success = checkedRead(aConvProcess->resumeFd, &aConvProcess->dataBuffer[0].used, sizeof(uint32_t)) && success;
//    success = checkedRead(aConvProcess->resumeFd, aConvProcess->dataBuffer[0].data, aConvProcess->dataBuffer[0].used) && success;

    return success;
}

bool openResumeFile(struct conversionParameters const *aParameters, struct DecryptProcess *aConvProcess) {
    bool createResumeFile = (!aParameters->resuming);
    int openFlags = createResumeFile ? (O_TRUNC | O_WRONLY | O_CREAT) : O_RDWR;

    /* Open resume file */
    aConvProcess->resumeFd = open(aParameters->resumeFilename, openFlags, 0600);
    if (aConvProcess->resumeFd == -1) {
        logmsg(LLVL_ERROR, "Opening '%s' for %s failed: %s\n", aParameters->resumeFilename, createResumeFile ? "writing" : "reading/writing", strerror(errno));
        return false;
    }

    if (createResumeFile) {
        /* Truncate resume file to zero and set to size of block */
        if (ftruncate(aConvProcess->resumeFd, 0) == -1) {
            logmsg(LLVL_ERROR, "Truncation of resume file failed: %s\n", strerror(errno));
            return false;
        }

        /* Write zeros in that resume file to assert we have the necessary disk
         * space available */
        if (!writeResumeFile(aConvProcess)) {
            logmsg(LLVL_ERROR, "Error writing the resume file: %s\n", strerror(errno));
            return false;
        }

        /* Then seek to start of resume file in case it needs to be written later on */
        if (lseek(aConvProcess->resumeFd, 0, SEEK_SET) == (off_t)-1) {
            logmsg(LLVL_ERROR, "Seek in resume file failed: %s\n", strerror(errno));
            return false;
        }
    }
    return true;
}

void checkDecryptCondition(struct conversionParameters const *aParameters) {
    bool abortProcess = false;
    bool isOpen = false;
    bool isMounted = false;

    /* Check if input device is Luks device */
    logmsg(LLVL_DEBUG, "Checking if device %s is already a LUKS device...\n", aParameters->rawDevice);
    if (!isLuks(aParameters->rawDevice)) {
        logmsg(LLVL_DEBUG, "%s: Not yet a LUKS device. -> Quit\n", aParameters->rawDevice);
        abortProcess = true;
        terminate(EC_PRECONDITIONS_NOT_SATISFIED);
    }

    /* todo: Check if input device  is open */


    /* todo: Check if Open device is mounted */

    /* Check passphrase */
    if (!aParameters->passphrase) {
        abortProcess = true;
        terminate(EC_PRECONDITIONS_NOT_SATISFIED);
    }
}

bool openLuks(const char *aBlkDevice, const char *passphrase, const char *aHandle) {
    const char *arguments[] = {
        "cryptsetup",
        "luksOpen",
        "--key-file",
        "-",
        aBlkDevice,
        aHandle,
        NULL
    };
    logmsg(LLVL_DEBUG, "Performing luksOpen of block device %s using passphrase %s and device mapper handle %s\n", aBlkDevice, passphrase, aHandle);
    struct execResult_t execResult = execInputPipeGetReturnCode(arguments, passphrase);
    if ((!execResult.success) || (execResult.returnCode != 0)) {
        logmsg(LLVL_ERROR, "luksOpen failed (execution %s, return code %d).\n", execResult.success ? "successful" : "failed", execResult.returnCode);
        return false;
    }

    return true;
}

bool openDevice(const char *aPath, int *aFd, int aOpenFlags, uint64_t *aDeviceSize) {
    /* Open device in requested mode first */
    *aFd = open(aPath, aOpenFlags, 0600);
    if (*aFd == -1) {
        logmsg(LLVL_ERROR, "open %s failed: %s\n", aPath, strerror(errno));
        return false;
    }

    /* Then determine its size */
    *aDeviceSize = getDiskSizeOfFd(*aFd);
    if (*aDeviceSize == 0) {
        logmsg(LLVL_ERROR, "Determine disk size of %s failed: %s\n", aPath, strerror(errno));
        return false;
    }

    return true;
}

bool saveDecryptDiskHeader(struct conversionParameters const *aParameters, struct DecryptProcess *aConvProcess) {
    logmsg(LLVL_INFO, "Backing up physical disk %s header to backup file %s\n", aParameters->rawDevice, aParameters->backupFile);

    if (doesFileExist(aParameters->backupFile)) {
        if (aParameters->safetyChecks) {
            logmsg(LLVL_ERROR, "Backup file %s already exists, refusing to overwrite.\n", aParameters->backupFile);
            return false;
        } else {
            logmsg(LLVL_WARN, "Backup file %s already exists. Overwriting because safety checks have been disabled.\n", aParameters->backupFile);
        }
    }

    /* Open raw disk for reading (cannot use aConvProcess->readDevFd here since
     * we might be doing reLUKSification) */
//    int readFd = open(aParameters->rawDevice, O_RDONLY);
    int readFd = aConvProcess->readDevFd;
    if (readFd == -1) {
        logmsg(LLVL_ERROR, "Opening raw disk device %s for reading failed: %s\n", aParameters->readDevice, strerror(errno));
        return false;
    }

    /* Open backup file */
    int writeFd = open(aParameters->backupFile, O_TRUNC | O_WRONLY | O_CREAT, 0600);
    if (writeFd == -1) {
        logmsg(LLVL_ERROR, "Opening backup file %s for writing failed: %s\n", aParameters->backupFile, strerror(errno));
        return false;
    }

    /* Determine the amount of blocks that need to be copied */
    int copyBlockCount = (DECRYPT_HEADER_SAVE_SIZE_BYTES < aConvProcess->readDevSize) ? DECRYPT_HEADER_SAVE_BLOCKCNT : (aConvProcess->readDevSize / DECRYPT_HEADER_SAVE_BLOCKSIZE);
    logmsg(LLVL_DEBUG, "Backup file %s will consist of %d blocks of %d bytes each (%d bytes total, %d kiB)\n", aParameters->backupFile, copyBlockCount, DECRYPT_HEADER_SAVE_BLOCKSIZE, copyBlockCount * DECRYPT_HEADER_SAVE_BLOCKSIZE, copyBlockCount * DECRYPT_HEADER_SAVE_BLOCKSIZE / 1024);

    /* Start copying */
    uint8_t copyBuffer[DECRYPT_HEADER_SAVE_BLOCKSIZE];
    for (int i = 0; i < copyBlockCount; i++) {
        if (!checkedRead(readFd, copyBuffer, DECRYPT_HEADER_SAVE_BLOCKSIZE)) {
            logmsg(LLVL_ERROR, "Read failed when trying to copy to backup file: %s\n", strerror(errno));
            return false;
        }
        if (!checkedWrite(writeFd, copyBuffer, DECRYPT_HEADER_SAVE_BLOCKSIZE)) {
            logmsg(LLVL_ERROR, "Write failed when trying to copy to backup file: %s\n", strerror(errno));
            return false;
        }
    }

    fsync(writeFd);
    close(writeFd);
    return true;
}

bool writeDecryptDiskHeader(struct conversionParameters const *aParameters, struct DecryptProcess *aConvProcess) {
    logmsg(LLVL_INFO, "Write header from backup file %s to physical disk %s\n", aParameters->backupFile, aParameters->rawDevice);

    if (!doesFileExist(aParameters->backupFile)) {
        return false;
    }

    int writeFd = aConvProcess->writeDevFd;
    if (writeFd == -1) {
        logmsg(LLVL_ERROR, "Opening raw disk device %s for reading failed: %s\n", aParameters->readDevice, strerror(errno));
        return false;
    }

    /* Then seek to start of device file to write header */
    if (lseek(aConvProcess->writeDevFd, 0, SEEK_SET) == (off_t)-1) {
        logmsg(LLVL_ERROR, "Seek in writeDevFd file failed: %s\n", strerror(errno));
        return false;
    }

    /* Open backup file */
    int readFd = open(aParameters->backupFile, O_RDONLY, 0600);
    if (readFd == -1) {
        logmsg(LLVL_ERROR, "Opening backup file %s for writing failed: %s\n", aParameters->backupFile, strerror(errno));
        return false;
    }

    /* Determine the amount of blocks that need to be copied */
    int copyBlockCount = (DECRYPT_HEADER_SAVE_SIZE_BYTES < aConvProcess->readDevSize) ? DECRYPT_HEADER_SAVE_BLOCKCNT : (aConvProcess->readDevSize / DECRYPT_HEADER_SAVE_BLOCKSIZE);
    logmsg(LLVL_DEBUG, "Backup file %s will consist of %d blocks of %d bytes each (%d bytes total, %d kiB)\n", aParameters->backupFile, copyBlockCount, DECRYPT_HEADER_SAVE_BLOCKSIZE, copyBlockCount * DECRYPT_HEADER_SAVE_BLOCKSIZE, copyBlockCount * DECRYPT_HEADER_SAVE_BLOCKSIZE / 1024);

    /* Start copying */
    uint8_t copyBuffer[DECRYPT_HEADER_SAVE_BLOCKSIZE];
    for (int i = 0; i < copyBlockCount; i++) {
        if (!checkedRead(readFd, copyBuffer, DECRYPT_HEADER_SAVE_BLOCKSIZE)) {
            logmsg(LLVL_ERROR, "Read failed when trying to copy to backup file: %s\n", strerror(errno));
            return false;
        }
        if (!checkedWrite(writeFd, copyBuffer, DECRYPT_HEADER_SAVE_BLOCKSIZE)) {
            logmsg(LLVL_ERROR, "Write failed when trying to copy to backup file: %s\n", strerror(errno));
            return false;
        }
    }

    close(readFd);
    return true;
}

bool generateRandomizedWriteHandle(struct DecryptProcess *decryptProcess) {
    strcpy(decryptProcess->readDevicePath, "/dev/mapper/luksipc_decrypt");
    if (!randomHexStrCat(decryptProcess->readDevicePath, 4)) {
        logmsg(LLVL_ERROR, "Cannot generate randomized luksipc write handle.\n");
        return false;
    }
    decryptProcess->readDeviceHandle = decryptProcess->readDevicePath + 12;
    return true;
}

static void showProgress(struct DecryptProcess *aConvProcess) {
    double curTime = getTime();
    if (aConvProcess->stats.startTime < 1) {
        aConvProcess->stats.startTime = curTime;
        aConvProcess->stats.lastOutOffset = aConvProcess->outOffset;
        aConvProcess->stats.lastShowTime = curTime;
    } else {
        uint64_t progressBytes = aConvProcess->outOffset - aConvProcess->stats.lastOutOffset;
        double progressTime = curTime - aConvProcess->stats.lastShowTime;

        bool showStats = ((progressBytes >= 100 * 1024 * 1024) && (progressTime >= 5));
        showStats = showStats || (progressTime >= 60);

        if (showStats) {
            double runtimeSeconds = curTime - aConvProcess->stats.startTime;
            int runtimeSecondsInteger = (int)runtimeSeconds;

            double copySpeedBytesPerSecond = 0;
            if (runtimeSeconds > 1) {
                copySpeedBytesPerSecond = (double)aConvProcess->stats.copied / runtimeSeconds;
            }

            uint64_t remainingBytes = aConvProcess->endOutOffset - aConvProcess->outOffset;

            double remainingSecs = 0;
            if (copySpeedBytesPerSecond > 10) {
                remainingSecs = (double)remainingBytes / copySpeedBytesPerSecond;
            }
            int remainingSecsInteger = 0;
            if ((remainingSecs > 0) && (remainingSecs < (100 * 3600))) {
                remainingSecsInteger = (int)remainingSecs;
            }

            logmsg(LLVL_INFO, "%2d:%02d: "
                       "%5.1f%%   "
                       "%7" PRIu64 " MiB / %" PRIu64 " MiB   "
                       "%5.1f MiB/s   "
                       "Left: "
                       "%7" PRIu64 " MiB "
                       "%2d:%02d h:m"
                       "\n",
                   runtimeSecondsInteger / 3600, runtimeSecondsInteger % 3600 / 60,
                   100.0 * (double)aConvProcess->outOffset / (double)aConvProcess->endOutOffset,
                   aConvProcess->outOffset / 1024 / 1024,
                   aConvProcess->endOutOffset / 1024 / 1024,
                   copySpeedBytesPerSecond / 1024. / 1024.,
                   remainingBytes / 1024 / 1024,
                   remainingSecsInteger / 3600, remainingSecsInteger % 3600 / 60
            );
            aConvProcess->stats.lastOutOffset = aConvProcess->outOffset;
            aConvProcess->stats.lastShowTime = curTime;
        }
    }
}

static enum copyResult_t issueGracefulShutdown(struct conversionParameters const *aParameters, struct DecryptProcess *decryptProcess) {
    logmsg(LLVL_INFO, "Gracefully shutting down.\n");
    if (!writeResumeFile(decryptProcess)) {
        logmsg(LLVL_WARN, "There were errors writing the resume file %s.\n", aParameters->resumeFilename);
        return COPYRESULT_ERROR_WRITING_RESUME_FILE;
    } else {
        logmsg(LLVL_INFO, "Successfully written resume file %s.\n", aParameters->resumeFilename);
        return COPYRESULT_SUCCESS_RESUMABLE;
    }
}

enum copyResult_t startDecryptDataCopy(struct conversionParameters const *aParameters, struct DecryptProcess *decryptProcess) {
    logmsg(LLVL_INFO, "Starting copying of data, read offset %" PRIu64 ", write offset %" PRIu64 "\n", decryptProcess->inOffset, decryptProcess->outOffset);

    while (true) {
        ssize_t bytesTransferred;
        int bytesToRead;

        if (REMAINING_BYTES(decryptProcess) < decryptProcess->dataBuffer.size) {
            /* Remaining is not a full chunk */
            bytesToRead = REMAINING_BYTES(decryptProcess);
            if (bytesToRead > 0) {
                logmsg(LLVL_DEBUG, "Preparing to write last (partial) chunk of %d bytes.\n", bytesToRead);
            }
        } else {
            bytesToRead = decryptProcess->dataBuffer.size;
        }

        if (bytesToRead > 0) {
            bytesTransferred = chunkReadAt(&decryptProcess->dataBuffer, decryptProcess->readDevFd, decryptProcess->inOffset, bytesToRead);

            if (bytesTransferred == -1) {
                /* Error reading from device, handle this! */
                logmsg(LLVL_ERROR, "Error reading from device at offset 0x%lx, will shutdown.\n", decryptProcess->inOffset);
                issueSigQuit();
                break;
            } else if (bytesTransferred > 0) {
                decryptProcess->inOffset += decryptProcess->dataBuffer.used;
            } else {
                logmsg(LLVL_WARN, "Read of %d transferred %d hit EOF at inOffset = %ld remaining = %ld\n", bytesToRead, bytesTransferred, decryptProcess->inOffset, REMAINING_BYTES(decryptProcess));
            }
        } else if (bytesToRead == 0) {
            logmsg(LLVL_DEBUG, "No more bytes to read, will finish writing last partial chunk of %d bytes.\n", REMAINING_BYTES(decryptProcess));
        } else {
            logmsg(LLVL_WARN, "Odd: %d bytes to read at inOffset = %ld remaining = %ld\n", bytesToRead, decryptProcess->inOffset, REMAINING_BYTES(decryptProcess));
        }

        if (receivedSigQuit()) {
            return issueGracefulShutdown(aParameters, decryptProcess);
        }

        bytesTransferred = chunkWriteAt(&decryptProcess->dataBuffer, decryptProcess->writeDevFd, decryptProcess->outOffset);

        if (bytesTransferred == -1) {
            logmsg(LLVL_ERROR, "Error writing to device at offset 0x%lx, shutting down.\n", decryptProcess->outOffset);
            return issueGracefulShutdown(aParameters, decryptProcess);
        } else if (bytesTransferred > 0) {
            decryptProcess->outOffset += bytesTransferred;
            decryptProcess->stats.copied += bytesTransferred;
            writeResumeFile(decryptProcess);
            showProgress(decryptProcess);
            if (decryptProcess->outOffset == decryptProcess->endOutOffset) {
                if (!writeDecryptDiskHeader(aParameters, decryptProcess)) {
                    terminate(EC_CANNOT_OPEN_BACKUP_HEADER_FILE);
                }

                logmsg(LLVL_INFO, "Disk copy completed successfully.\n");
                return COPYRESULT_SUCCESS_FINISHED;
            }
            decryptProcess->dataBuffer.used = 0;
        }
    }
    return COPYRESULT_ERROR_WRITING_RESUME_FILE;
}

void decrypt(struct conversionParameters const *parameters) {
    struct DecryptProcess decryptProcess;
    memset(&decryptProcess, 0, sizeof(struct DecryptProcess));

    checkDecryptCondition(parameters);

    if (!allocChunk(&decryptProcess.dataBuffer, parameters->blocksize)) {
        logmsg(LLVL_ERROR, "Failed to allocate chunk buffer: %s\n", strerror(errno));
        terminate(EC_CANNOT_ALLOCATE_CHUNK_MEMORY);
    }

    /* open device to write decrypt data */
    if (!openDevice(parameters->rawDevice, &decryptProcess.writeDevFd, O_RDWR, &decryptProcess.writeDevSize)) {
        terminate(EC_CANNOT_OPEN_WRITE_DEVICE);
    }

    if (decryptProcess.writeDevSize < (uint32_t)parameters->blocksize) {
        logmsg(LLVL_ERROR, "Error: Volume size of %s (%" PRIu64 " bytes) is smaller than chunksize (%u). Weird and unsupported corner case.\n", parameters->rawDevice, decryptProcess.writeDevSize, parameters->blocksize);
        terminate(EC_UNSUPPORTED_SMALL_DISK_CORNER_CASE);
    }

    /* Generate a randomized conversion handle */
    if (!generateRandomizedWriteHandle(&decryptProcess)) {
        terminate(EC_CANNOT_GENERATE_WRITE_HANDLE);
    }

    /* Check availability of device mapper handle before performing format */
    if (!isLuksMapperAvailable(decryptProcess.readDeviceHandle)) {
        logmsg(LLVL_ERROR, "Error: luksipc conversion handle '%s' not available.\n", decryptProcess.readDeviceHandle);
        terminate(EC_LUKSIPC_WRITE_DEVICE_HANDLE_UNAVAILABLE);
    }

    /* open Luks device */
    if (!openLuks(parameters->readDevice, parameters->passphrase, decryptProcess.readDeviceHandle)) {
        terminate(EC_FAILED_TO_PERFORM_LUKSOPEN);
    }

    /* open mapper device for read unencrypt data */
    if (!openDevice(decryptProcess.readDevicePath, &decryptProcess.readDevFd, O_RDWR, &decryptProcess.readDevSize)) {
        terminate(EC_CANNOT_OPEN_READ_DEVICE);
    }

    /* Open resume file for writing (conversion) or reading/writing (resume) */
    if (!openResumeFile(parameters, &decryptProcess)) {
        terminate(EC_CANNOT_OPEN_RESUME_FILE);
    }

    /* Do a backup of the physical disk first if we're just starting out our
	 * conversion */
    if (!parameters->resuming) {
        if (!saveDecryptDiskHeader(parameters, &decryptProcess)) {
            terminate(EC_FAILED_TO_BACKUP_HEADER);
        }
    }

    if (!parameters->resuming) {
        decryptProcess.outOffset = (DECRYPT_HEADER_SAVE_SIZE_BYTES < decryptProcess.readDevSize) ? DECRYPT_HEADER_SAVE_SIZE_BYTES : decryptProcess.readDevSize;
        decryptProcess.inOffset = decryptProcess.outOffset;
    } else {
        /* Now it's time to read in the resume file. */
        if (!readResumeFile(parameters, &decryptProcess)) {
            logmsg(LLVL_ERROR, "Failed to read resume file, aborting.\n");
            terminate(EC_FAILED_TO_READ_RESUME_FILE);
        }
        decryptProcess.inOffset = decryptProcess.outOffset;
    }

    /* copy process */
    decryptProcess.endOutOffset = (decryptProcess.readDevSize < decryptProcess.writeDevSize) ? decryptProcess.readDevSize : decryptProcess.writeDevSize;

    enum copyResult_t copyResult = startDecryptDataCopy(parameters, &decryptProcess);
    if (copyResult !=  COPYRESULT_SUCCESS_FINISHED) {
        terminate(EC_COPY_ABORTED_FAILED_TO_WRITE_WRITE_RESUME_FILE);
    }

    /* Sync the disk and close open file descriptors to partition */
    logmsg(LLVL_DEBUG, "Closing read/write file descriptors %d and %d.\n", decryptProcess.readDevFd, decryptProcess.writeDevFd);
    close(decryptProcess.readDevFd);
    close(decryptProcess.writeDevFd);
    decryptProcess.readDevFd = -1;
    decryptProcess.writeDevFd = -1;

    logmsg(LLVL_INFO, "Synchronizing disk...\n");
    sync();
    logmsg(LLVL_INFO, "Synchronizing of disk finished.\n");

    /* Then close the LUKS device */
    if (!dmRemove(decryptProcess.readDeviceHandle)) {
        logmsg(LLVL_ERROR, "Failed to close LUKS device %s.\n", decryptProcess.readDeviceHandle);
        terminate(EC_FAILED_TO_CLOSE_LUKS_DEVICE);
    }

    /* Free memory of copy buffers */
    freeChunk(&decryptProcess.dataBuffer);

    /* Return with a code that depends on whether the copying was finished
 * completely or if it was aborted gracefully (i.e. resuming is possible)
 **/
    terminate((copyResult == COPYRESULT_SUCCESS_FINISHED) ? EC_SUCCESS : EC_COPY_ABORTED_RESUME_FILE_WRITTEN);
}