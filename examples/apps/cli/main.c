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

#include <stdio.h>
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
#include <openthread/srp_client.h>
#include <openthread/random_crypto.h>
#include <openthread/link.h>

#include "openthread-system.h"
#include "cli/cli_config.h"
#include "common/code_utils.hpp"

#include "lib/platform/reset_util.h"

#define TCP_PORT 4443

#define OPENTHREAD_FTD 1

char hex_lookup[16] = {
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    'A',
    'B',
    'C',
    'D',
    'E',
    'F',
};

size_t bytes_to_hex_string(char *output, size_t output_length, const char *bytes, size_t bytes_length) {
    if (output_length < bytes_length * 2 + 1) {
        otCliOutputFormat("bad hex buffer size\n");
        return 0;
    }
    size_t output_index = 0;
    for (int i = 0 ; i < bytes_length ; i++) {
        output[output_index++] = hex_lookup[bytes[i] >> 4];
        output[output_index++] = hex_lookup[bytes[i] & 0xF];
    }
    output[output_index] = '\0';
    return output_index;
}

void handleNetifStateChanged(uint32_t aFlags, void *aContext);

/**
 * Initializes the CLI app.
 *
 * @param[in]  aInstance  The OpenThread instance structure.
 */
extern void otAppCliInit(otInstance *aInstance);

#if OPENTHREAD_CONFIG_HEAP_EXTERNAL_ENABLE
OT_TOOL_WEAK void *otPlatCAlloc(size_t aNum, size_t aSize) { return calloc(aNum, aSize); }

OT_TOOL_WEAK void otPlatFree(void *aPtr) { free(aPtr); }
#endif

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

#if OPENTHREAD_FTD || OPENTHREAD_MTD
    otTcpCircularSendBuffer send_buffer;
#endif
    uint8_t                 internal_send_buffer[1024];
    uint8_t                 _PADDING[128];
    uint8_t                 internal_receive_buffer[128];
} endpoint_state_t;

endpoint_state_t            endpoints_states[10];

#if OPENTHREAD_FTD || OPENTHREAD_MTD
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

int find_newline(const uint8_t *buffer, size_t bufsize) {
    for (int i = 0 ; i < bufsize ; i++) {
        if (buffer[i] == '\r' || buffer[i] == '\n') {
            return i;
        }
    }
    return -1;
}

uint8_t tmp[1024];

void read_and_echo_bytes(otTcpEndpoint *endpoint)
{
    const otLinkedBuffer *buffer  = NULL;
    size_t                written = 0;
    endpoint_state_t     *context = (endpoint_state_t *)endpoint->mContext;
    otTcpReceiveContiguify(endpoint);
    otTcpReceiveByReference(endpoint, &buffer);

    // find newline
    int newline_index = find_newline(buffer->mData, buffer->mLength);
    if (newline_index != -1) {
        memcpy(&tmp, buffer->mData, newline_index + 1);
        tmp[newline_index] = '\0';
        otCliInputLine(tmp);
        otTcpCommitReceive(endpoint, newline_index + 1, 0);
        if (context->fin_received && written == context->bytes_available)
        {
            // TODO: end of stream is sent before the actual returned output data are received from the cli
            otTcpSendEndOfStream(endpoint);
            context->fin_sent = true;
        }
    }

    // otCliOutputFormat("before, cicrular buffer free size = %d, contains %d bytes, start: %d: %.*s\r\n",
    //                     otTcpCircularSendBufferGetFreeSpace(&context->send_buffer),
    //                     context->send_buffer.mCapacityUsed, context->send_buffer.mStartIndex,
    //                     context->send_buffer.mCapacityUsed, context->send_buffer.mDataBuffer);
    // otError err = otTcpCircularSendBufferWrite(endpoint, &context->send_buffer, "hello", strlen("hello"), &written,
    // 0);

    // otCliOutputFormat("cicrular buffer err: %d, free size: %d, contains %d bytes, start: %d: %.*s\r\n", err,
    //                     otTcpCircularSendBufferGetFreeSpace(&context->send_buffer),
    //                     context->send_buffer.mCapacityUsed, context->send_buffer.mStartIndex,
    //                     context->send_buffer.mCapacityUsed, context->send_buffer.mDataBuffer);
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
    read_and_echo_bytes(endpoint);
}

void tcp_disconnected(otTcpEndpoint *endpoint, otTcpDisconnectedReason reason)
{
    // TODO
}

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

int CliUartOutput(void *aContext, const char *aFormat, va_list aArguments);
void otAppCliInitWithCallback(otInstance *aInstance, otCliOutputCallback aCallback);
int OutputCallback(void *aContext, const char *aFormat, va_list aArguments)
{   
    for (int i = 0 ; i < n_endpoints ; i++) {
        endpoint_state_t *context = &endpoints_states[i];
        size_t written = vsprintf(tmp, aFormat, aArguments);
        otTcpCircularSendBufferWrite(&endpoints[i], &context->send_buffer, tmp, written, &written, 0);
    }
    return CliUartOutput(aContext, aFormat, aArguments);
}
#endif //OPENTHREAD_FTD || OPENTHREAD_MTD


#if OPENTHREAD_FTD || OPENTHREAD_MTD
char server_ipv6_addr_str[256];
// char instance_name[128];
// char host_name[128];
otExtAddress instance_eui;
char instance_name_prefix[128] = "my instance name - ";
char instance_name[sizeof(instance_name_prefix) + 2 * sizeof(otExtAddress)]; // space to store the name prefix and the hex-encoded EUI64
int server_port;
otSrpClientService service;
otDnsTxtEntry entry;
FILE *out;
bool service_registered = false;

 void on_thread_state_changed(otChangedFlags aFlags, void *aContext) {
    otInstance *instance = (otInstance *) aContext;
    otCliOutputFormat("state changed: %d!\n", aFlags);
    if (aFlags & OT_CHANGED_THREAD_ROLE) {
        // otCliOutputFormat("role changed: %d!\n", aFlags);
        otSrpClientStop(instance);
        otDeviceRole role = otThreadGetDeviceRole(instance);
        otCliOutputFormat("role = %d!\n", role);
        // fflush(out);
        if (!service_registered && role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER || role == OT_DEVICE_ROLE_LEADER) {
            // if there's at least one arg, register the service
            // int pid = getpid();
            // int n = snprintf(instance_name, sizeof(instance_name), "mock-service-instance-%d", pid);
            // if (n >= sizeof(instance_name)) {
            //     otCliOutputFormat("could not setup the device's instance name\n");
            //     return;
            // }

            // automatically choose the host address to announce through SRP (probably
            // mesh-local or ULA if there is one)
            otError err = otSrpClientEnableAutoHostAddress(instance);
            if (err != OT_ERROR_NONE) {
                otCliOutputFormat("could not enable client's auto host address: %d\n", err);
                return;
            }

            // n = snprintf(host_name, sizeof(host_name), "mock-service-%d", pid);
            // if (n >= sizeof(host_name)) {
            //     otCliOutputFormat("could not setup the device's host name\n");
            //     return;
            // }

            size_t instance_name_prefix_len = strlen(instance_name_prefix);
            char *instance_name_hex = &instance_name[instance_name_prefix_len];
            err = otSrpClientSetHostName(instance, instance_name_hex);

            entry.mKey = "mock-arbitrary-key";
            entry.mValue = NULL;
            entry.mValueLength = 0;
            service.mInstanceName = instance_name;
            service.mName = "_unsecure-cli._tcp";
            service.mPort = TCP_PORT;
            service.mTxtEntries = &entry;
            service.mNumTxtEntries = 1;
            err = otSrpClientAddService(instance, &service);
            if (err != OT_ERROR_NONE) {
                otCliOutputFormat("could not add client service: %d\n", err);
                return;
            }
            otSrpClientEnableAutoStartMode(instance, NULL, NULL);
            service_registered = true;
            // otSockAddr server_addr;
            // err = otIp6AddressFromString(server_ipv6_addr_str, &server_addr.mAddress);
            // if (err != OT_ERROR_NONE) {
            //     otCliOutputFormat("could not parse the server IP address: %d\n", err);
            //     return;
            // }
            // server_addr.mPort = server_port;
            // err = otSrpClientStart(instance, &server_addr);
            // if (err != OT_ERROR_NONE) {
            //     otCliOutputFormat("could not start the SRP client: %d\n", err);
            //     return;
            // }
        }
    }
 }
 #endif


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


#if OPENTHREAD_FTD || OPENTHREAD_MTD
    strncpy(instance_name, instance_name_prefix, sizeof(instance_name_prefix) - 1);
    size_t instance_name_prefix_len = strlen(instance_name_prefix);
    char *instance_name_hex = &instance_name[instance_name_prefix_len];
    otLinkGetFactoryAssignedIeeeEui64(instance, &instance_eui);
    bytes_to_hex_string(instance_name_hex, sizeof(instance_name) - instance_name_prefix_len, instance_eui.m8, sizeof(instance_eui.m8));
    otAppCliInitWithCallback(instance, &OutputCallback);
    initTcp(instance);
    otError err = otSetStateChangedCallback(instance, on_thread_state_changed, instance);
    if (err != OT_ERROR_NONE) {
        fprintf(out, "could set state changed callback: %d\n", err);
    }
#else
    otAppCliInit(instance);
#endif

#if OPENTHREAD_POSIX && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    IgnoreError(otCliSetUserCommands(kCommands, OT_ARRAY_LENGTH(kCommands), instance));
#endif

#if OPENTHREAD_CONFIG_PLATFORM_LOG_CRASH_DUMP_ENABLE
    IgnoreError(otPlatLogCrashDump());
#endif

#if OPENTHREAD_FTD || OPENTHREAD_MTD
    otError error = otIp6SetEnabled(instance, true);
    assert(error == OT_ERROR_NONE);
    error = otThreadSetEnabled(instance, true);
    assert(error == OT_ERROR_NONE);
#endif // OPENTHREAD_FTD || OPENTHREAD_MTD

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
