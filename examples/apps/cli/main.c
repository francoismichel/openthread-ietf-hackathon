/*
 *  Copyright (c) 2016, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <string.h>
#ifdef __linux__
#include <signal.h>
#include <sys/prctl.h>
#endif

#include <openthread-core-config.h>
#include <openthread/config.h>

#include <openthread/cli.h>
#include <openthread/diag.h>
#include <openthread/instance.h>
#include <openthread/tasklet.h>
#include <openthread/tcp.h>
#include <openthread/tcp_ext.h>
#include <openthread/thread.h>
#include <openthread/thread_ftd.h>
#include <openthread/platform/logging.h>
#include <openthread/platform/misc.h>

#include "openthread-system.h"
#include "cli/cli_config.h"
#include "common/code_utils.hpp"

#include "lib/platform/reset_util.h"

void handleNetifStateChanged(uint32_t aFlags, void *aContext);

/**
 * Initializes the CLI app.
 *
 * @param[in]  aInstance  The OpenThread instance structure.
 *
 */
extern void otAppCliInit(otInstance *aInstance);

#if OPENTHREAD_CONFIG_HEAP_EXTERNAL_ENABLE
OT_TOOL_WEAK void *otPlatCAlloc(size_t aNum, size_t aSize) { return calloc(aNum, aSize); }

OT_TOOL_WEAK void otPlatFree(void *aPtr) { free(aPtr); }
#endif

void otTaskletsSignalPending(otInstance *aInstance) { OT_UNUSED_VARIABLE(aInstance); }

#if OPENTHREAD_POSIX && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
static otError ProcessExit(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    OT_UNUSED_VARIABLE(aContext);
    OT_UNUSED_VARIABLE(aArgsLength);
    OT_UNUSED_VARIABLE(aArgs);

    exit(EXIT_SUCCESS);
}

#if OPENTHREAD_EXAMPLES_SIMULATION
extern otError ProcessNodeIdFilter(void *aContext, uint8_t aArgsLength, char *aArgs[]);
#endif

static const otCliCommand kCommands[] = {
    {"exit", ProcessExit},
#if OPENTHREAD_EXAMPLES_SIMULATION
    /*
     * The CLI command `nodeidfilter` only works for simulation in real time.
     *
     * It can be used either as an allow list or a deny list. Once the filter is cleared, the first `nodeidfilter allow`
     * or `nodeidfilter deny` will determine whether it is set up as an allow or deny list. Subsequent calls should
     * use the same sub-command to add new node IDs, e.g., if we first call `nodeidfilter allow` (which sets the filter
     * up  as an allow list), a subsequent `nodeidfilter deny` will result in `InvalidState` error.
     *
     * The usage of the command `nodeidfilter`:
     *     - `nodeidfilter deny <nodeid>` :  It denies the connection to a specified node (use as deny-list).
     *     - `nodeidfilter allow <nodeid> :  It allows the connection to a specified node (use as allow-list).
     *     - `nodeidfilter clear`         :  It restores the filter state to default.
     *     - `nodeidfilter`               :  Outputs filter mode (allow-list or deny-list) and filtered node IDs.
     */
    {"nodeidfilter", ProcessNodeIdFilter},
#endif
};
#endif // OPENTHREAD_POSIX && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)

static otTcpListener tcpListener;
otInstance          *instance;

otTcpEndpoint endpoints[10];
size_t        n_endpoints = 0;

typedef struct endpoint_state
{
    size_t                  n_read;
    size_t                  n_received;
    size_t                  n_sent;
    size_t                  n_commited;
    size_t                  fin_received;
    size_t                  fin_sent;
    size_t                  bytes_available;
    otTcpCircularSendBuffer send_buffer;
    uint8_t                 internal_send_buffer[128];
    uint8_t                 _PADDING[128];
    uint8_t                 internal_receive_buffer[128];
} endpoint_state_t;

endpoint_state_t            endpoints_states[10];
otTcpEndpointInitializeArgs endpoints_args[10];

otTcpListenerInitializeArgs listenerArgs;

void tcp_established(otTcpEndpoint *endpoint)
{
    // noop
}

void tcp_send_done_callback(otTcpEndpoint *endpoint, otLinkedBuffer *buffer)
{
    // NOOP
}

void read_and_echo_bytes(otTcpEndpoint *endpoint)
{
    const otLinkedBuffer *buffer  = NULL;
    size_t                written = 0;
    endpoint_state_t     *context = (endpoint_state_t *)endpoint->mContext;
    // otTcpReceiveContiguify(endpoint);
    otTcpReceiveByReference(endpoint, &buffer);

    otCliOutputFormat("received %d bytes: %.*s\r\n", buffer->mLength, buffer->mLength, buffer->mData);

    // otCliOutputFormat("before, cicrular buffer free size = %d, contains %d bytes, start: %d: %.*s\r\n",
    //                     otTcpCircularSendBufferGetFreeSpace(&context->send_buffer),
    //                     context->send_buffer.mCapacityUsed, context->send_buffer.mStartIndex,
    //                     context->send_buffer.mCapacityUsed, context->send_buffer.mDataBuffer);
    otTcpCircularSendBufferWrite(endpoint, &context->send_buffer, buffer->mData, buffer->mLength, &written, 0);
    // otError err = otTcpCircularSendBufferWrite(endpoint, &context->send_buffer, "hello", strlen("hello"), &written,
    // 0);

    // otCliOutputFormat("cicrular buffer err: %d, free size: %d, contains %d bytes, start: %d: %.*s\r\n", err,
    //                     otTcpCircularSendBufferGetFreeSpace(&context->send_buffer),
    //                     context->send_buffer.mCapacityUsed, context->send_buffer.mStartIndex,
    //                     context->send_buffer.mCapacityUsed, context->send_buffer.mDataBuffer);
    if (context->fin_received && written == context->bytes_available)
    {
        otTcpSendEndOfStream(endpoint);
        context->fin_sent = true;
    }
    otTcpCommitReceive(endpoint, written, 0);
}

void tcp_forward_progress(otTcpEndpoint *endpoint, size_t aInSendBuffer, size_t aBacklog)
{
    endpoint_state_t *context = (endpoint_state_t *)endpoint->mContext;
    otTcpCircularSendBufferHandleForwardProgress(&context->send_buffer, aInSendBuffer);
    if (otTcpCircularSendBufferGetFreeSpace(&context->send_buffer) > 0 && context->bytes_available > 0 ||
        (context->bytes_available == 0 && context->fin_received && !context->fin_sent))
    {
        read_and_echo_bytes(endpoint);
    }
}

void tcp_receive_available(otTcpEndpoint *endpoint, size_t bytes_available, bool fin, size_t bytes_remaining)
{
    endpoint_state_t *context = (endpoint_state_t *)endpoint->mContext;
    context->bytes_available  = bytes_available;
    context->fin_received     = fin;
    otCliOutputFormat("receive available\r\n");
    read_and_echo_bytes(endpoint);
}

void tcp_disconnected(otTcpEndpoint *endpoint, otTcpDisconnectedReason reason)
{
    // TODO
}

#define TCP_PORT 4443

otTcpIncomingConnectionAction acceptReady(otTcpListener    *aListener,
                                          const otSockAddr *aPeer,
                                          otTcpEndpoint   **aAcceptInto)
{
    otPlatLog(OT_LOG_LEVEL_CRIT, OT_LOG_REGION_CLI, "new TCP connection!\n");
    otCliOutputFormat("New TCP connection\r\n");
    if (n_endpoints == 10)
        return OT_TCP_INCOMING_CONNECTION_ACTION_DEFER;
    otTcpEndpoint    *endpoint = &endpoints[n_endpoints];
    endpoint_state_t *context  = &endpoints_states[n_endpoints];
    // context = endpoint index

    otTcpEndpointInitializeArgs *endpointArgs = &endpoints_args[n_endpoints];
    endpointArgs->mContext                    = (void *)context;
    endpointArgs->mDisconnectedCallback       = &tcp_disconnected;
    endpointArgs->mEstablishedCallback        = &tcp_established;
    endpointArgs->mForwardProgressCallback    = &tcp_forward_progress;
    endpointArgs->mReceiveAvailableCallback   = &tcp_receive_available;
    endpointArgs->mSendDoneCallback           = &tcp_send_done_callback;
    endpointArgs->mReceiveBufferSize          = sizeof(context->internal_receive_buffer);
    endpointArgs->mReceiveBuffer              = context->internal_receive_buffer;

    otTcpCircularSendBufferInitialize(&context->send_buffer, context->internal_send_buffer,
                                      sizeof(context->internal_send_buffer));
    otCliOutputFormat("initialized, cicrular buffer free size = %d, contains %d bytes, start: %d\r\n",
                      otTcpCircularSendBufferGetFreeSpace(&context->send_buffer), context->send_buffer.mCapacityUsed,
                      context->send_buffer.mStartIndex);
    otTcpEndpointInitialize(instance, endpoint, endpointArgs);
    *aAcceptInto = endpoint;
    n_endpoints++;
    return OT_TCP_INCOMING_CONNECTION_ACTION_ACCEPT;
}

void acceptDone(otTcpListener *aListener, otTcpEndpoint *aEndpoint, const otSockAddr *aPeer)
{
    // nothing to do, we implement echo
    otCliOutputFormat("accept done\r\n");
}

/**
 * Initialize TCP socket
 */
void initTcp(otInstance *aInstance)
{
    otPlatLog(OT_LOG_LEVEL_CRIT, OT_LOG_REGION_CLI, "TCP init\n");
    otSockAddr listenSockAddr;

    memset(&tcpListener, 0, sizeof(tcpListener));
    memset(&listenSockAddr, 0, sizeof(listenSockAddr));

    listenSockAddr.mPort = TCP_PORT;

    listenerArgs.mAcceptDoneCallback  = &acceptDone;
    listenerArgs.mAcceptReadyCallback = &acceptReady;

    // TODO: initialize callbacks in args
    if (!otTcpListenerInitialize(aInstance, &tcpListener, &listenerArgs))
    {
        // TODO
    }
    otTcpListen(&tcpListener, &listenSockAddr);
}

int main(int argc, char *argv[])
{
#ifdef __linux__
    // Ensure we terminate this process if the
    // parent process dies.
    prctl(PR_SET_PDEATHSIG, SIGHUP);
#endif

    OT_SETUP_RESET_JUMP(argv);

#if OPENTHREAD_CONFIG_MULTIPLE_INSTANCE_ENABLE
    size_t   otInstanceBufferLength = 0;
    uint8_t *otInstanceBuffer       = NULL;
#endif

pseudo_reset:

    otSysInit(argc, argv);

#if OPENTHREAD_CONFIG_MULTIPLE_INSTANCE_ENABLE
    // Call to query the buffer size
    (void)otInstanceInit(NULL, &otInstanceBufferLength);

    // Call to allocate the buffer
    otInstanceBuffer = (uint8_t *)malloc(otInstanceBufferLength);
    assert(otInstanceBuffer);

    // Initialize OpenThread with the buffer
    instance = otInstanceInit(otInstanceBuffer, &otInstanceBufferLength);
#else
    instance = otInstanceInitSingle();
#endif
    assert(instance);

    otAppCliInit(instance);
    initTcp(instance);

#if OPENTHREAD_POSIX && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    IgnoreError(otCliSetUserCommands(kCommands, OT_ARRAY_LENGTH(kCommands), instance));
#endif

#if OPENTHREAD_CONFIG_PLATFORM_LOG_CRASH_DUMP_ENABLE
    IgnoreError(otPlatLogCrashDump());
#endif

    while (!otSysPseudoResetWasRequested())
    {
        otTaskletsProcess(instance);
        otSysProcessDrivers(instance);
    }

    otInstanceFinalize(instance);
#if OPENTHREAD_CONFIG_MULTIPLE_INSTANCE_ENABLE
    free(otInstanceBuffer);
#endif

    goto pseudo_reset;

    return 0;
}

#if OPENTHREAD_CONFIG_LOG_OUTPUT == OPENTHREAD_CONFIG_LOG_OUTPUT_APP
void otPlatLog(otLogLevel aLogLevel, otLogRegion aLogRegion, const char *aFormat, ...)
{
    va_list ap;

    va_start(ap, aFormat);
    otCliPlatLogv(aLogLevel, aLogRegion, aFormat, ap);
    va_end(ap);
}
#endif
