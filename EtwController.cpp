/*
The BSD 3-Clause License

Copyright (c) 2016 Egtra All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of {{ project }} nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "stdafx.h"
#include <initguid.h>
#include <winevt.h>
#include <netcfgx.h>
#include <evntrace.h>
#include <wrl/client.h>

#include "EtwCommon.h"

#pragma comment(lib, "wevtapi.lib")

using namespace std::literals;

struct ServiceHandleDeleter
{
	typedef SC_HANDLE pointer;
	void operator()(_In_opt_ SC_HANDLE hsc) const noexcept
	{
		if (hsc != nullptr)
		{
			CloseServiceHandle(hsc);
		}
	}
};

using service_handle = std::unique_ptr<SC_HANDLE, ServiceHandleDeleter>;

struct HKeyDeleter
{
	typedef HKEY pointer;
	void operator()(_In_opt_ HKEY hk) const noexcept
	{
		if (hk != nullptr)
		{
			RegCloseKey(hk);
		}
	}
};

using hkey = std::unique_ptr<HKEY, HKeyDeleter>;

union EventTracePropertiesWithBuffer
{
	// buffer size: EVENT_TRACE_PROPERTIES + logFileName + sessionName
	char buffer[sizeof(EVENT_TRACE_PROPERTIES) + (1024 + 1024) * sizeof(WCHAR)];
	EVENT_TRACE_PROPERTIES etp;
};

// {2ED6006E-4729-4609-B423-3EE7BCD678EF}
static constexpr GUID GUID_Microsoft_Windows_NDIS_PacketCapture = { 0x2ED6006E, 0x4729, 0x4609,{ 0xB4, 0x23, 0x3E, 0xE7, 0xBC, 0xD6, 0x78, 0xEF } };

static DWORD StartNdisCapService()
{
	service_handle hscm(OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT));
	ATLENSURE_RETURN_VAL(hscm != nullptr, GetLastError());
	service_handle hsc(OpenService(hscm.get(), L"ndiscap", SERVICE_START));
	ATLENSURE_RETURN_VAL(hsc != nullptr, GetLastError());
	return StartService(hsc.get(), 0, nullptr);
}

static DWORD SetNdisCapParameters(bool enable)
{
	ATL::CRegKey key;
	auto lstatusCreate = key.Create(
		HKEY_LOCAL_MACHINE,
		LR"(System\CurrentControlSet\Services\NdisCap\Parameters)");
	ATLENSURE_RETURN_VAL(lstatusCreate == ERROR_SUCCESS, lstatusCreate);

	DWORD refCount;
	auto lstatusQuery = key.QueryDWORDValue(L"RefCount", refCount);
	ATLENSURE_RETURN_VAL(lstatusQuery == ERROR_SUCCESS, lstatusQuery);

	if (enable)
	{
		++refCount;
		auto lstatusSetRefCount = key.SetDWORDValue(L"RefCount", refCount);
		ATLENSURE_RETURN_VAL(lstatusSetRefCount == ERROR_SUCCESS, lstatusSetRefCount);
	}
	else
	{
		if (refCount > 0)
		{
			--refCount;
			auto lstatusSetRefCount = key.SetDWORDValue(L"RefCount", refCount);
			ATLENSURE_RETURN_VAL(lstatusSetRefCount == ERROR_SUCCESS, lstatusSetRefCount);
		}
	}

	if (enable)
	{
		auto lstatusSetCaptureMode = key.SetDWORDValue(L"CaptureMode", 0);
		ATLENSURE_RETURN_VAL(lstatusSetCaptureMode == ERROR_SUCCESS, lstatusSetCaptureMode);
	}

	return ERROR_SUCCESS;
}

static DWORD EnableCapture(bool enable)
{
	Microsoft::WRL::ComPtr<INetCfg> nc;
	auto hrCreate = CoCreateInstance(CLSID_CNetCfg, nullptr, CLSCTX_SERVER, IID_PPV_ARGS(&nc));
	ATLENSURE_RETURN_HR(SUCCEEDED(hrCreate), hrCreate);

	Microsoft::WRL::ComPtr<INetCfgLock> lock;
	auto hrQueryL = nc.As(&lock);
	ATLENSURE_RETURN_HR(SUCCEEDED(hrQueryL), hrQueryL);

	auto hrLock = lock->AcquireWriteLock(5000, L"NdisCapPacket", nullptr);
	ATLENSURE_RETURN_HR(SUCCEEDED(hrLock), hrLock);

	auto hrInit = nc->Initialize(nullptr);
	ATLENSURE_RETURN_HR(SUCCEEDED(hrInit), hrInit);

	Microsoft::WRL::ComPtr<INetCfgComponent> ndisCap;
	auto hrFind = nc->FindComponent(L"ms_ndiscap", &ndisCap);
	ATLENSURE_RETURN_HR(SUCCEEDED(hrFind), hrFind);

	Microsoft::WRL::ComPtr<INetCfgComponentBindings> bindings;
	auto hrQueryB = ndisCap.As(&bindings);
	ATLENSURE_RETURN_HR(SUCCEEDED(hrQueryB), hrQueryB);

	Microsoft::WRL::ComPtr<IEnumNetCfgBindingPath> enumBindingPath;
	auto hrEnum = bindings->EnumBindingPaths(EBP_BELOW, &enumBindingPath);
	ATLENSURE_RETURN_HR(SUCCEEDED(hrEnum), hrEnum);

	for (;;)
	{
		ATL::CComPtr<INetCfgBindingPath> bindingPath;
		ULONG fetched;
		auto hrNext = enumBindingPath->Next(1, &bindingPath, &fetched);
		ATLENSURE_RETURN_HR(SUCCEEDED(hrNext), hrNext);
		if (hrNext != S_OK)
		{
			break;
		}

		auto hrEnable = bindingPath->Enable(static_cast<BOOL>(enable));
		ATLENSURE_RETURN_HR(SUCCEEDED(hrEnable), hrEnable);
	}
	auto hrApply = nc->Apply();
	ATLENSURE_RETURN_HR(SUCCEEDED(hrApply), hrApply);

	ATL::CRegKey session;
	auto lstatusCreate = session.Create(
		HKEY_CURRENT_USER,
		LR"(System\CurrentControlSet\Control\NetTrace\Session)",
		nullptr,
		REG_OPTION_NON_VOLATILE,
		KEY_SET_VALUE);
	ATLENSURE_RETURN_VAL(lstatusCreate == ERROR_SUCCESS, lstatusCreate);

	auto lstatusSet = session.SetDWORDValue(L"CaptureEnabled", 1u);
	ATLENSURE_RETURN_VAL(lstatusSet == ERROR_SUCCESS, lstatusSet);

	auto hrReleaseLock = lock->ReleaseWriteLock();
	ATLENSURE_RETURN_HR(SUCCEEDED(hrReleaseLock), hrReleaseLock);

	auto hrUninit = nc->Uninitialize();
	ATLENSURE_RETURN_HR(SUCCEEDED(hrUninit), hrUninit);

	return S_OK;
}

static std::pair<DWORD, TRACEHANDLE> StartTrace()
{
	TRACEHANDLE th;
	EventTracePropertiesWithBuffer buffer{};
	buffer.etp.Wnode.BufferSize = sizeof buffer;
	buffer.etp.Wnode.ClientContext = 2; // Query perfomance counter
	buffer.etp.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	buffer.etp.BufferSize = 128;
	buffer.etp.MaximumBuffers = 128;
	buffer.etp.MaximumFileSize = 250;
	buffer.etp.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	buffer.etp.LoggerNameOffset = sizeof buffer.etp;
	auto resultStartTrace = StartTrace(&th, SessionName, &buffer.etp);
	if (resultStartTrace == ERROR_ALREADY_EXISTS)
	{
		auto resultControlTrace = ControlTrace(0, SessionName, &buffer.etp, EVENT_TRACE_CONTROL_STOP);
		ATLENSURE_RETURN_VAL(resultControlTrace == ERROR_SUCCESS, std::make_pair(resultControlTrace, TRACEHANDLE()));
		resultStartTrace = StartTrace(&th, SessionName, &buffer.etp);
	}
	ATLENSURE_RETURN_VAL(resultStartTrace == ERROR_SUCCESS, std::make_pair(resultStartTrace, TRACEHANDLE()));

	ENABLE_TRACE_PARAMETERS params{};
	params.Version = ENABLE_TRACE_PARAMETERS_VERSION;
	auto resultEnableTrace = EnableTraceEx2(th,
		&GUID_Microsoft_Windows_NDIS_PacketCapture,
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_INFORMATION,
		0,
		0,
		0,
		&params);
	ATLENSURE_RETURN_VAL(resultEnableTrace == ERROR_SUCCESS, std::make_pair(resultEnableTrace, TRACEHANDLE()));

	return{ ERROR_SUCCESS, th };
}

std::pair<DWORD, TRACEHANDLE> StartCapture()
{
	for (;;)
	{
		auto resultService = StartNdisCapService();
		if (resultService == ERROR_SUCCESS)
		{
			break;
		}
		else if (resultService == ERROR_INVALID_FUNCTION)
		{
			Sleep(50);
			continue;
		}
		return{ resultService, TRACEHANDLE() };
	}

	auto resultParameters = SetNdisCapParameters(true);
	ATLENSURE_RETURN_VAL(resultParameters == ERROR_SUCCESS, std::make_pair(resultParameters, TRACEHANDLE()));

	auto resultCapture = EnableCapture(true);
	ATLENSURE_RETURN_VAL(resultCapture == ERROR_SUCCESS, std::make_pair(resultCapture, TRACEHANDLE()));

	return StartTrace();
}

void StopCapture(_In_ TRACEHANDLE th)
{
	EventTracePropertiesWithBuffer buffer{};
	buffer.etp.Wnode.BufferSize = sizeof buffer;
	buffer.etp.LoggerNameOffset = sizeof buffer.etp;
	buffer.etp.LogFileNameOffset = sizeof buffer.etp + 1024 * sizeof (WCHAR);
	ControlTrace(th, nullptr, &buffer.etp, EVENT_TRACE_CONTROL_STOP);

	EnableCapture(false);
	SetNdisCapParameters(false);
}
