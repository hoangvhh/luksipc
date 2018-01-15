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

#include "decrypt.h"

#define REMAINING_BYTES(aconvptr)		(((aconvptr)->endOutOffset) - ((aconvptr)->outOffset))

struct DecryptProcess {
    int readDevFd, writeDevFd;
    uint64_t readDevSize, writeDevSize;
    struct chunk dataBuffer;
//    int usedBufferIndex;
//    int resumeFd;
//    char *rawDeviceAlias;
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
    /* todo: open Luks partition with passphrase */
    const char *arguments[] = {
        "echo",
        "-n",
        passphrase,
        "|",
        "cryptsetup",
        "luksOpen",
        "--key-file",
        "-",
        aBlkDevice,
        aHandle,
        NULL
    };
    logmsg(LLVL_DEBUG, "Performing luksOpen of block device %s using passphrase %s and device mapper handle %s\n", aBlkDevice, passphrase, aHandle);
    struct execResult_t execResult = execGetReturnCode(arguments);
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

bool generateRandomizedWriteHandle(struct DecryptProcess *decryptProcess) {
    strcpy(decryptProcess->readDevicePath, "/dev/mapper/luksipc_decrypt");
    if (!randomHexStrCat(decryptProcess->readDevicePath, 4)) {
        logmsg(LLVL_ERROR, "Cannot generate randomized luksipc write handle.\n");
        return false;
    }
    decryptProcess->readDeviceHandle = decryptProcess->readDevicePath + 12;
    return true;
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
//                issueSigQuit();
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

        bytesTransferred = chunkWriteAt(&decryptProcess->dataBuffer, decryptProcess->writeDevFd, decryptProcess->outOffset);

        if (bytesTransferred == -1) {
            logmsg(LLVL_ERROR, "Error writing to device at offset 0x%lx, shutting down.\n", decryptProcess->outOffset);
//            return issueGracefulShutdown(aParameters, aConvProcess);
            break;
        } else if (bytesTransferred > 0) {
            decryptProcess->outOffset += bytesTransferred;
            decryptProcess->stats.copied += bytesTransferred;
//            showProgress(aConvProcess);
            if (decryptProcess->outOffset == decryptProcess->endOutOffset) {
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
    if (!openDevice(parameters->readDevice, &decryptProcess.writeDevFd, O_RDWR, &decryptProcess.writeDevSize)) {
        terminate(EC_CANNOT_OPEN_WRITE_DEVICE);
    }

    if (decryptProcess.writeDevSize < (uint32_t)parameters->blocksize) {
        logmsg(LLVL_ERROR, "Error: Volume size of %s (%" PRIu64 " bytes) is smaller than chunksize (%u). Weird and unsupported corner case.\n", parameters->readDevice, decryptProcess.readDevSize, parameters->blocksize);
        terminate(EC_UNSUPPORTED_SMALL_DISK_CORNER_CASE);
    }

    generateRandomizedWriteHandle(&decryptProcess);

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

    /* copy process */
    decryptProcess.endOutOffset = (decryptProcess.readDevSize < decryptProcess.writeDevSize) ? decryptProcess.readDevSize : decryptProcess.writeDevSize;
    decryptProcess.outOffset = 0;
    decryptProcess.inOffset = 0;

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