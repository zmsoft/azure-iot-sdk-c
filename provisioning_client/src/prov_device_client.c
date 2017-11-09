// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h> 

#include <signal.h>
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/lock.h"
#include "azure_c_shared_utility/xlogging.h"

#include "../inc/azure_prov_client/prov_device_ll_client.h"
#include "../inc/azure_prov_client/prov_device_client.h"
#include "azure_c_shared_utility/vector.h"

typedef struct PROV_DEVICE_INSTANCE_TAG
{
    PROV_DEVICE_LL_HANDLE ProvDeviceLLHandle;
    THREAD_HANDLE ThreadHandle;
    LOCK_HANDLE LockHandle;
    sig_atomic_t StopThread;
} PROV_DEVICE_INSTANCE;

#define USER_CALLBACK_TYPE_VALUES           \
    CALLBACK_TYPE_REGISTER_DEVICE_CALLBACK, \
    CALLBACK_TYPE_REGISTER_STATUS_CALLBACK

DEFINE_ENUM(USER_CALLBACK_TYPE, USER_CALLBACK_TYPE_VALUES)
DEFINE_ENUM_STRINGS(USER_CALLBACK_TYPE, USER_CALLBACK_TYPE_VALUES)


static int ScheduleWork_Thread(void* threadArgument)
{
    PROV_DEVICE_INSTANCE* prov_device_instance = (PROV_DEVICE_INSTANCE*)threadArgument;

    while (1)
    {
        if (Lock(prov_device_instance->LockHandle) == LOCK_OK)
        {
            if (prov_device_instance->StopThread)
            {
                (void)Unlock(prov_device_instance->LockHandle);
                break; /*gets out of the thread*/
            }
            else
            {
                Prov_Device_LL_DoWork(prov_device_instance->ProvDeviceLLHandle);
                (void)Unlock(prov_device_instance->LockHandle);
            }
        }
        else
        {
            LogError("Lock failed, shall retry");
        }
        (void)ThreadAPI_Sleep(1);
    }

    ThreadAPI_Exit(0);
    return 0;
}

static PROV_DEVICE_RESULT StartWorkerThreadIfNeeded(PROV_DEVICE_INSTANCE* prov_device_instance)
{
    PROV_DEVICE_RESULT result;
    if (prov_device_instance->ThreadHandle == NULL)
    {
        prov_device_instance->StopThread = 0;
        if (ThreadAPI_Create(&prov_device_instance->ThreadHandle, ScheduleWork_Thread, prov_device_instance) != THREADAPI_OK)
        {
            LogError("ThreadAPI_Create failed");
            result = PROV_DEVICE_RESULT_ERROR;
        }
        else
        {
            result = PROV_DEVICE_RESULT_OK;
        }
    }
    else
    {
        result = PROV_DEVICE_RESULT_OK;
    }
    return result;
}

PROV_DEVICE_HANDLE Prov_Device_Create(const char* uri, const char* scope_id, PROV_DEVICE_TRANSPORT_PROVIDER_FUNCTION protocol)
{
    PROV_DEVICE_INSTANCE* result;

    if (uri == NULL || scope_id == NULL || protocol == NULL)
    {
        LogError("Invalid parameter specified uri: %p, scope_id: %p, protocol: %p", uri, scope_id, protocol);
        result = NULL;
    }
    else
    {
        result = (PROV_DEVICE_INSTANCE*)malloc(sizeof(PROV_DEVICE_INSTANCE));
        if (result == NULL)
        {
            LogError("Unable to allocate Instance Info");
        }
        else
        {
            result->LockHandle = Lock_Init();
            if (result->LockHandle == NULL)
            {
                LogError("Lock_Init failed");
                free(result);
                result = NULL;
            }
            else
            {
                result->ProvDeviceLLHandle = Prov_Device_LL_Create(uri, scope_id, protocol);
                result->ThreadHandle = NULL;
                result->StopThread = 0;
            }
        }
    }

    return result;
}

void Prov_Device_Destroy(PROV_DEVICE_HANDLE prov_device_handle)
{
    if (prov_device_handle == NULL)
    {
        LogError("NULL prov_device_handle");
    }
    else
    {
        PROV_DEVICE_INSTANCE* prov_device_instance = (PROV_DEVICE_INSTANCE*)prov_device_handle;

        if (Lock(prov_device_handle->LockHandle) != LOCK_OK)
        {
            LogError("Could not acquire lock");
            prov_device_handle->StopThread = 1; /*setting it even when Lock fails*/
        }
        else
        {
            prov_device_handle->StopThread = 1;

            /*Codes_SRS_IOTHUBMESSAGING_12_022: [ IoTHubMessaging_Close shall be made thread-safe by using the lock created in IoTHubMessaging_Create. ]*/
            (void)Unlock(prov_device_handle->LockHandle);
        }

        if (prov_device_handle->ThreadHandle != NULL)
        {
            int res;
            /*Codes_SRS_IOTHUBMESSAGING_12_013: [ The thread created as part of executing IoTHubMessaging_SendAsync shall be joined. ]*/
            if (ThreadAPI_Join(prov_device_handle->ThreadHandle, &res) != THREADAPI_OK)
            {
                LogError("ThreadAPI_Join failed");
            }
        }

        Prov_Device_LL_Destroy(prov_device_instance->ProvDeviceLLHandle);

        Lock_Deinit(prov_device_instance->LockHandle);

        free(prov_device_instance);
    }
}

PROV_DEVICE_RESULT Prov_Device_Register_Device(PROV_DEVICE_HANDLE prov_device_handle, PROV_DEVICE_CLIENT_REGISTER_DEVICE_CALLBACK register_callback, void* user_context, PROV_DEVICE_CLIENT_REGISTER_STATUS_CALLBACK register_status_callback, void* status_user_context)
{
    PROV_DEVICE_RESULT result;

    if (prov_device_handle == NULL)
    {
        LogError("NULL prov_device_handle");
        result = PROV_DEVICE_RESULT_INVALID_ARG;
    }
    else
    { 
        PROV_DEVICE_INSTANCE* prov_device_instance = (PROV_DEVICE_INSTANCE*)prov_device_handle;

        if ((result = StartWorkerThreadIfNeeded(prov_device_instance)) != PROV_DEVICE_RESULT_OK)
        {
            LogError("Could not start worker thread");
            result = PROV_DEVICE_RESULT_ERROR;
        }
        else
        {
            if (Lock(prov_device_instance->LockHandle) != LOCK_OK)
            {
                LogError("Could not acquire lock");
                result = PROV_DEVICE_RESULT_ERROR;
            }
            else
            {
                result = Prov_Device_LL_Register_Device(prov_device_instance->ProvDeviceLLHandle, register_callback, user_context, register_status_callback, status_user_context);

                (void)Unlock(prov_device_instance->LockHandle);
            }
        }
    }

    return result;
}

PROV_DEVICE_RESULT Prov_Device_SetOption(PROV_DEVICE_HANDLE prov_device_handle, const char* optionName, const void* value)
{
    PROV_DEVICE_RESULT result;

    if (prov_device_handle == NULL)
    {
        result = PROV_DEVICE_RESULT_INVALID_ARG;
        LogError("NULL prov_device_handle");
    }
    else if (optionName == NULL)
    {
        result = PROV_DEVICE_RESULT_INVALID_ARG;
        LogError("NULL optionName");
    }
    else if (value == NULL)
    {
        result = PROV_DEVICE_RESULT_INVALID_ARG;
        LogError("NULL value");
    }
    else
    {
        PROV_DEVICE_INSTANCE* prov_device_instance = (PROV_DEVICE_INSTANCE*)prov_device_handle;

        result = Prov_Device_LL_SetOption(prov_device_instance->ProvDeviceLLHandle, optionName, value);
    }

    return result;
}

const char* Prov_Device_GetVersionString(void)
{
    return Prov_Device_LL_GetVersionString();
}

