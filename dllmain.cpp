#include <Windows.h>
#include "main.h"

#pragma region Proxy
struct powrprof_dll {
	HMODULE dll;
	FARPROC oCallNtPowerInformation;
	FARPROC oCanUserWritePwrScheme;
	FARPROC oDeletePwrScheme;
	FARPROC oDevicePowerClose;
	FARPROC oDevicePowerEnumDevices;
	FARPROC oDevicePowerOpen;
	FARPROC oDevicePowerSetDeviceState;
	FARPROC oEnumPwrSchemes;
	FARPROC oGUIDFormatToGlobalPowerPolicy;
	FARPROC oGUIDFormatToPowerPolicy;
	FARPROC oGetActivePwrScheme;
	FARPROC oGetCurrentPowerPolicies;
	FARPROC oGetPwrCapabilities;
	FARPROC oGetPwrDiskSpindownRange;
	FARPROC oIsAdminOverrideActive;
	FARPROC oIsPwrHibernateAllowed;
	FARPROC oIsPwrShutdownAllowed;
	FARPROC oIsPwrSuspendAllowed;
	FARPROC oLoadCurrentPwrScheme;
	FARPROC oMergeLegacyPwrScheme;
	FARPROC oPowerApplyPowerRequestOverride;
	FARPROC oPowerApplySettingChanges;
	FARPROC oPowerCanRestoreIndividualDefaultPowerScheme;
	FARPROC oPowerClearUserAwayPrediction;
	FARPROC oPowerCloseEnvironmentalMonitor;
	FARPROC oPowerCloseLimitsMitigation;
	FARPROC oPowerCloseLimitsPolicy;
	FARPROC oPowerCreatePossibleSetting;
	FARPROC oPowerCreateSetting;
	FARPROC oPowerDebugDifPowerPolicies;
	FARPROC oPowerDebugDifSystemPowerPolicies;
	FARPROC oPowerDebugDumpPowerPolicy;
	FARPROC oPowerDebugDumpPowerScheme;
	FARPROC oPowerDebugDumpSystemPowerCapabilities;
	FARPROC oPowerDebugDumpSystemPowerPolicy;
	FARPROC oPowerDeleteScheme;
	FARPROC oPowerDeterminePlatformRole;
	FARPROC oPowerDeterminePlatformRoleEx;
	FARPROC oPowerDuplicateScheme;
	FARPROC oPowerEnumerate;
	FARPROC oPowerGetActiveScheme;
	FARPROC oPowerGetActualOverlayScheme;
	FARPROC oPowerGetAdaptiveStandbyDiagnostics;
	FARPROC oPowerGetEffectiveOverlayScheme;
	FARPROC oPowerGetOverlaySchemes;
	FARPROC oPowerGetUserAwayMinPredictionConfidence;
	FARPROC oPowerImportPowerScheme;
	FARPROC oPowerInformationWithPrivileges;
	FARPROC oPowerIsSettingRangeDefined;
	FARPROC oPowerOpenSystemPowerKey;
	FARPROC oPowerOpenUserPowerKey;
	FARPROC oPowerPolicyToGUIDFormat;
	FARPROC oPowerReadACDefaultIndex;
	FARPROC oPowerReadACValue;
	FARPROC oPowerReadACValueIndex;
	FARPROC oPowerReadACValueIndexEx;
	FARPROC oPowerReadDCDefaultIndex;
	FARPROC oPowerReadDCValue;
	FARPROC oPowerReadDCValueIndex;
	FARPROC oPowerReadDCValueIndexEx;
	FARPROC oPowerReadDescription;
	FARPROC oPowerReadFriendlyName;
	FARPROC oPowerReadIconResourceSpecifier;
	FARPROC oPowerReadPossibleDescription;
	FARPROC oPowerReadPossibleFriendlyName;
	FARPROC oPowerReadPossibleValue;
	FARPROC oPowerReadSecurityDescriptor;
	FARPROC oPowerReadSettingAttributes;
	FARPROC oPowerReadValueIncrement;
	FARPROC oPowerReadValueMax;
	FARPROC oPowerReadValueMin;
	FARPROC oPowerReadValueUnitsSpecifier;
	FARPROC oPowerReapplyActiveScheme;
	FARPROC oPowerRegisterEnvironmentalMonitor;
	FARPROC oPowerRegisterForEffectivePowerModeNotifications;
	FARPROC oPowerRegisterLimitsMitigation;
	FARPROC oPowerRegisterLimitsPolicy;
	FARPROC oPowerRegisterSuspendResumeNotification;
	FARPROC oPowerRemovePowerSetting;
	FARPROC oPowerReplaceDefaultPowerSchemes;
	FARPROC oPowerReportLimitsEvent;
	FARPROC oPowerReportThermalEvent;
	FARPROC oPowerRestoreACDefaultIndex;
	FARPROC oPowerRestoreDCDefaultIndex;
	FARPROC oPowerRestoreDefaultPowerSchemes;
	FARPROC oPowerRestoreIndividualDefaultPowerScheme;
	FARPROC oPowerSetActiveOverlayScheme;
	FARPROC oPowerSetActiveScheme;
	FARPROC oPowerSetAlsBrightnessOffset;
	FARPROC oPowerSetBrightnessAndTransitionTimes;
	FARPROC oPowerSetUserAwayPrediction;
	FARPROC oPowerSettingAccessCheck;
	FARPROC oPowerSettingAccessCheckEx;
	FARPROC oPowerSettingRegisterNotification;
	FARPROC oPowerSettingRegisterNotificationEx;
	FARPROC oPowerSettingUnregisterNotification;
	FARPROC oPowerUnregisterFromEffectivePowerModeNotifications;
	FARPROC oPowerUnregisterSuspendResumeNotification;
	FARPROC oPowerUpdateEnvironmentalMonitorState;
	FARPROC oPowerUpdateEnvironmentalMonitorThresholds;
	FARPROC oPowerUpdateLimitsMitigation;
	FARPROC oPowerWriteACDefaultIndex;
	FARPROC oPowerWriteACValueIndex;
	FARPROC oPowerWriteDCDefaultIndex;
	FARPROC oPowerWriteDCValueIndex;
	FARPROC oPowerWriteDescription;
	FARPROC oPowerWriteFriendlyName;
	FARPROC oPowerWriteIconResourceSpecifier;
	FARPROC oPowerWritePossibleDescription;
	FARPROC oPowerWritePossibleFriendlyName;
	FARPROC oPowerWritePossibleValue;
	FARPROC oPowerWriteSecurityDescriptor;
	FARPROC oPowerWriteSettingAttributes;
	FARPROC oPowerWriteValueIncrement;
	FARPROC oPowerWriteValueMax;
	FARPROC oPowerWriteValueMin;
	FARPROC oPowerWriteValueUnitsSpecifier;
	FARPROC oReadGlobalPwrPolicy;
	FARPROC oReadProcessorPwrScheme;
	FARPROC oReadPwrScheme;
	FARPROC oSetActivePwrScheme;
	FARPROC oSetSuspendState;
	FARPROC oValidatePowerPolicies;
	FARPROC oWriteGlobalPwrPolicy;
	FARPROC oWriteProcessorPwrScheme;
	FARPROC oWritePwrScheme;
} powrprof;

extern "C" {
	FARPROC PA = 0;
	int runASM();

	void fCallNtPowerInformation() { PA = powrprof.oCallNtPowerInformation; runASM(); }
	void fCanUserWritePwrScheme() { PA = powrprof.oCanUserWritePwrScheme; runASM(); }
	void fDeletePwrScheme() { PA = powrprof.oDeletePwrScheme; runASM(); }
	void fDevicePowerClose() { PA = powrprof.oDevicePowerClose; runASM(); }
	void fDevicePowerEnumDevices() { PA = powrprof.oDevicePowerEnumDevices; runASM(); }
	void fDevicePowerOpen() { PA = powrprof.oDevicePowerOpen; runASM(); }
	void fDevicePowerSetDeviceState() { PA = powrprof.oDevicePowerSetDeviceState; runASM(); }
	void fEnumPwrSchemes() { PA = powrprof.oEnumPwrSchemes; runASM(); }
	void fGUIDFormatToGlobalPowerPolicy() { PA = powrprof.oGUIDFormatToGlobalPowerPolicy; runASM(); }
	void fGUIDFormatToPowerPolicy() { PA = powrprof.oGUIDFormatToPowerPolicy; runASM(); }
	void fGetActivePwrScheme() { PA = powrprof.oGetActivePwrScheme; runASM(); }
	void fGetCurrentPowerPolicies() { PA = powrprof.oGetCurrentPowerPolicies; runASM(); }
	void fGetPwrCapabilities() { PA = powrprof.oGetPwrCapabilities; runASM(); }
	void fGetPwrDiskSpindownRange() { PA = powrprof.oGetPwrDiskSpindownRange; runASM(); }
	void fIsAdminOverrideActive() { PA = powrprof.oIsAdminOverrideActive; runASM(); }
	void fIsPwrHibernateAllowed() { PA = powrprof.oIsPwrHibernateAllowed; runASM(); }
	void fIsPwrShutdownAllowed() { PA = powrprof.oIsPwrShutdownAllowed; runASM(); }
	void fIsPwrSuspendAllowed() { PA = powrprof.oIsPwrSuspendAllowed; runASM(); }
	void fLoadCurrentPwrScheme() { PA = powrprof.oLoadCurrentPwrScheme; runASM(); }
	void fMergeLegacyPwrScheme() { PA = powrprof.oMergeLegacyPwrScheme; runASM(); }
	void fPowerApplyPowerRequestOverride() { PA = powrprof.oPowerApplyPowerRequestOverride; runASM(); }
	void fPowerApplySettingChanges() { PA = powrprof.oPowerApplySettingChanges; runASM(); }
	void fPowerCanRestoreIndividualDefaultPowerScheme() { PA = powrprof.oPowerCanRestoreIndividualDefaultPowerScheme; runASM(); }
	void fPowerClearUserAwayPrediction() { PA = powrprof.oPowerClearUserAwayPrediction; runASM(); }
	void fPowerCloseEnvironmentalMonitor() { PA = powrprof.oPowerCloseEnvironmentalMonitor; runASM(); }
	void fPowerCloseLimitsMitigation() { PA = powrprof.oPowerCloseLimitsMitigation; runASM(); }
	void fPowerCloseLimitsPolicy() { PA = powrprof.oPowerCloseLimitsPolicy; runASM(); }
	void fPowerCreatePossibleSetting() { PA = powrprof.oPowerCreatePossibleSetting; runASM(); }
	void fPowerCreateSetting() { PA = powrprof.oPowerCreateSetting; runASM(); }
	void fPowerDebugDifPowerPolicies() { PA = powrprof.oPowerDebugDifPowerPolicies; runASM(); }
	void fPowerDebugDifSystemPowerPolicies() { PA = powrprof.oPowerDebugDifSystemPowerPolicies; runASM(); }
	void fPowerDebugDumpPowerPolicy() { PA = powrprof.oPowerDebugDumpPowerPolicy; runASM(); }
	void fPowerDebugDumpPowerScheme() { PA = powrprof.oPowerDebugDumpPowerScheme; runASM(); }
	void fPowerDebugDumpSystemPowerCapabilities() { PA = powrprof.oPowerDebugDumpSystemPowerCapabilities; runASM(); }
	void fPowerDebugDumpSystemPowerPolicy() { PA = powrprof.oPowerDebugDumpSystemPowerPolicy; runASM(); }
	void fPowerDeleteScheme() { PA = powrprof.oPowerDeleteScheme; runASM(); }
	void fPowerDeterminePlatformRole() { PA = powrprof.oPowerDeterminePlatformRole; runASM(); }
	void fPowerDeterminePlatformRoleEx() { PA = powrprof.oPowerDeterminePlatformRoleEx; runASM(); }
	void fPowerDuplicateScheme() { PA = powrprof.oPowerDuplicateScheme; runASM(); }
	void fPowerEnumerate() { PA = powrprof.oPowerEnumerate; runASM(); }
	void fPowerGetActiveScheme() { PA = powrprof.oPowerGetActiveScheme; runASM(); }
	void fPowerGetActualOverlayScheme() { PA = powrprof.oPowerGetActualOverlayScheme; runASM(); }
	void fPowerGetAdaptiveStandbyDiagnostics() { PA = powrprof.oPowerGetAdaptiveStandbyDiagnostics; runASM(); }
	void fPowerGetEffectiveOverlayScheme() { PA = powrprof.oPowerGetEffectiveOverlayScheme; runASM(); }
	void fPowerGetOverlaySchemes() { PA = powrprof.oPowerGetOverlaySchemes; runASM(); }
	void fPowerGetUserAwayMinPredictionConfidence() { PA = powrprof.oPowerGetUserAwayMinPredictionConfidence; runASM(); }
	void fPowerImportPowerScheme() { PA = powrprof.oPowerImportPowerScheme; runASM(); }
	void fPowerInformationWithPrivileges() { PA = powrprof.oPowerInformationWithPrivileges; runASM(); }
	void fPowerIsSettingRangeDefined() { PA = powrprof.oPowerIsSettingRangeDefined; runASM(); }
	void fPowerOpenSystemPowerKey() { PA = powrprof.oPowerOpenSystemPowerKey; runASM(); }
	void fPowerOpenUserPowerKey() { PA = powrprof.oPowerOpenUserPowerKey; runASM(); }
	void fPowerPolicyToGUIDFormat() { PA = powrprof.oPowerPolicyToGUIDFormat; runASM(); }
	void fPowerReadACDefaultIndex() { PA = powrprof.oPowerReadACDefaultIndex; runASM(); }
	void fPowerReadACValue() { PA = powrprof.oPowerReadACValue; runASM(); }
	void fPowerReadACValueIndex() { PA = powrprof.oPowerReadACValueIndex; runASM(); }
	void fPowerReadACValueIndexEx() { PA = powrprof.oPowerReadACValueIndexEx; runASM(); }
	void fPowerReadDCDefaultIndex() { PA = powrprof.oPowerReadDCDefaultIndex; runASM(); }
	void fPowerReadDCValue() { PA = powrprof.oPowerReadDCValue; runASM(); }
	void fPowerReadDCValueIndex() { PA = powrprof.oPowerReadDCValueIndex; runASM(); }
	void fPowerReadDCValueIndexEx() { PA = powrprof.oPowerReadDCValueIndexEx; runASM(); }
	void fPowerReadDescription() { PA = powrprof.oPowerReadDescription; runASM(); }
	void fPowerReadFriendlyName() { PA = powrprof.oPowerReadFriendlyName; runASM(); }
	void fPowerReadIconResourceSpecifier() { PA = powrprof.oPowerReadIconResourceSpecifier; runASM(); }
	void fPowerReadPossibleDescription() { PA = powrprof.oPowerReadPossibleDescription; runASM(); }
	void fPowerReadPossibleFriendlyName() { PA = powrprof.oPowerReadPossibleFriendlyName; runASM(); }
	void fPowerReadPossibleValue() { PA = powrprof.oPowerReadPossibleValue; runASM(); }
	void fPowerReadSecurityDescriptor() { PA = powrprof.oPowerReadSecurityDescriptor; runASM(); }
	void fPowerReadSettingAttributes() { PA = powrprof.oPowerReadSettingAttributes; runASM(); }
	void fPowerReadValueIncrement() { PA = powrprof.oPowerReadValueIncrement; runASM(); }
	void fPowerReadValueMax() { PA = powrprof.oPowerReadValueMax; runASM(); }
	void fPowerReadValueMin() { PA = powrprof.oPowerReadValueMin; runASM(); }
	void fPowerReadValueUnitsSpecifier() { PA = powrprof.oPowerReadValueUnitsSpecifier; runASM(); }
	void fPowerReapplyActiveScheme() { PA = powrprof.oPowerReapplyActiveScheme; runASM(); }
	void fPowerRegisterEnvironmentalMonitor() { PA = powrprof.oPowerRegisterEnvironmentalMonitor; runASM(); }
	void fPowerRegisterForEffectivePowerModeNotifications() { PA = powrprof.oPowerRegisterForEffectivePowerModeNotifications; runASM(); }
	void fPowerRegisterLimitsMitigation() { PA = powrprof.oPowerRegisterLimitsMitigation; runASM(); }
	void fPowerRegisterLimitsPolicy() { PA = powrprof.oPowerRegisterLimitsPolicy; runASM(); }
	void fPowerRegisterSuspendResumeNotification() { PA = powrprof.oPowerRegisterSuspendResumeNotification; runASM(); }
	void fPowerRemovePowerSetting() { PA = powrprof.oPowerRemovePowerSetting; runASM(); }
	void fPowerReplaceDefaultPowerSchemes() { PA = powrprof.oPowerReplaceDefaultPowerSchemes; runASM(); }
	void fPowerReportLimitsEvent() { PA = powrprof.oPowerReportLimitsEvent; runASM(); }
	void fPowerReportThermalEvent() { PA = powrprof.oPowerReportThermalEvent; runASM(); }
	void fPowerRestoreACDefaultIndex() { PA = powrprof.oPowerRestoreACDefaultIndex; runASM(); }
	void fPowerRestoreDCDefaultIndex() { PA = powrprof.oPowerRestoreDCDefaultIndex; runASM(); }
	void fPowerRestoreDefaultPowerSchemes() { PA = powrprof.oPowerRestoreDefaultPowerSchemes; runASM(); }
	void fPowerRestoreIndividualDefaultPowerScheme() { PA = powrprof.oPowerRestoreIndividualDefaultPowerScheme; runASM(); }
	void fPowerSetActiveOverlayScheme() { PA = powrprof.oPowerSetActiveOverlayScheme; runASM(); }
	void fPowerSetActiveScheme() { PA = powrprof.oPowerSetActiveScheme; runASM(); }
	void fPowerSetAlsBrightnessOffset() { PA = powrprof.oPowerSetAlsBrightnessOffset; runASM(); }
	void fPowerSetBrightnessAndTransitionTimes() { PA = powrprof.oPowerSetBrightnessAndTransitionTimes; runASM(); }
	void fPowerSetUserAwayPrediction() { PA = powrprof.oPowerSetUserAwayPrediction; runASM(); }
	void fPowerSettingAccessCheck() { PA = powrprof.oPowerSettingAccessCheck; runASM(); }
	void fPowerSettingAccessCheckEx() { PA = powrprof.oPowerSettingAccessCheckEx; runASM(); }
	void fPowerSettingRegisterNotification() { PA = powrprof.oPowerSettingRegisterNotification; runASM(); }
	void fPowerSettingRegisterNotificationEx() { PA = powrprof.oPowerSettingRegisterNotificationEx; runASM(); }
	void fPowerSettingUnregisterNotification() { PA = powrprof.oPowerSettingUnregisterNotification; runASM(); }
	void fPowerUnregisterFromEffectivePowerModeNotifications() { PA = powrprof.oPowerUnregisterFromEffectivePowerModeNotifications; runASM(); }
	void fPowerUnregisterSuspendResumeNotification() { PA = powrprof.oPowerUnregisterSuspendResumeNotification; runASM(); }
	void fPowerUpdateEnvironmentalMonitorState() { PA = powrprof.oPowerUpdateEnvironmentalMonitorState; runASM(); }
	void fPowerUpdateEnvironmentalMonitorThresholds() { PA = powrprof.oPowerUpdateEnvironmentalMonitorThresholds; runASM(); }
	void fPowerUpdateLimitsMitigation() { PA = powrprof.oPowerUpdateLimitsMitigation; runASM(); }
	void fPowerWriteACDefaultIndex() { PA = powrprof.oPowerWriteACDefaultIndex; runASM(); }
	void fPowerWriteACValueIndex() { PA = powrprof.oPowerWriteACValueIndex; runASM(); }
	void fPowerWriteDCDefaultIndex() { PA = powrprof.oPowerWriteDCDefaultIndex; runASM(); }
	void fPowerWriteDCValueIndex() { PA = powrprof.oPowerWriteDCValueIndex; runASM(); }
	void fPowerWriteDescription() { PA = powrprof.oPowerWriteDescription; runASM(); }
	void fPowerWriteFriendlyName() { PA = powrprof.oPowerWriteFriendlyName; runASM(); }
	void fPowerWriteIconResourceSpecifier() { PA = powrprof.oPowerWriteIconResourceSpecifier; runASM(); }
	void fPowerWritePossibleDescription() { PA = powrprof.oPowerWritePossibleDescription; runASM(); }
	void fPowerWritePossibleFriendlyName() { PA = powrprof.oPowerWritePossibleFriendlyName; runASM(); }
	void fPowerWritePossibleValue() { PA = powrprof.oPowerWritePossibleValue; runASM(); }
	void fPowerWriteSecurityDescriptor() { PA = powrprof.oPowerWriteSecurityDescriptor; runASM(); }
	void fPowerWriteSettingAttributes() { PA = powrprof.oPowerWriteSettingAttributes; runASM(); }
	void fPowerWriteValueIncrement() { PA = powrprof.oPowerWriteValueIncrement; runASM(); }
	void fPowerWriteValueMax() { PA = powrprof.oPowerWriteValueMax; runASM(); }
	void fPowerWriteValueMin() { PA = powrprof.oPowerWriteValueMin; runASM(); }
	void fPowerWriteValueUnitsSpecifier() { PA = powrprof.oPowerWriteValueUnitsSpecifier; runASM(); }
	void fReadGlobalPwrPolicy() { PA = powrprof.oReadGlobalPwrPolicy; runASM(); }
	void fReadProcessorPwrScheme() { PA = powrprof.oReadProcessorPwrScheme; runASM(); }
	void fReadPwrScheme() { PA = powrprof.oReadPwrScheme; runASM(); }
	void fSetActivePwrScheme() { PA = powrprof.oSetActivePwrScheme; runASM(); }
	void fSetSuspendState() { PA = powrprof.oSetSuspendState; runASM(); }
	void fValidatePowerPolicies() { PA = powrprof.oValidatePowerPolicies; runASM(); }
	void fWriteGlobalPwrPolicy() { PA = powrprof.oWriteGlobalPwrPolicy; runASM(); }
	void fWriteProcessorPwrScheme() { PA = powrprof.oWriteProcessorPwrScheme; runASM(); }
	void fWritePwrScheme() { PA = powrprof.oWritePwrScheme; runASM(); }
}

void setupFunctions() {
	powrprof.oCallNtPowerInformation = GetProcAddress(powrprof.dll, "CallNtPowerInformation");
	powrprof.oCanUserWritePwrScheme = GetProcAddress(powrprof.dll, "CanUserWritePwrScheme");
	powrprof.oDeletePwrScheme = GetProcAddress(powrprof.dll, "DeletePwrScheme");
	powrprof.oDevicePowerClose = GetProcAddress(powrprof.dll, "DevicePowerClose");
	powrprof.oDevicePowerEnumDevices = GetProcAddress(powrprof.dll, "DevicePowerEnumDevices");
	powrprof.oDevicePowerOpen = GetProcAddress(powrprof.dll, "DevicePowerOpen");
	powrprof.oDevicePowerSetDeviceState = GetProcAddress(powrprof.dll, "DevicePowerSetDeviceState");
	powrprof.oEnumPwrSchemes = GetProcAddress(powrprof.dll, "EnumPwrSchemes");
	powrprof.oGUIDFormatToGlobalPowerPolicy = GetProcAddress(powrprof.dll, "GUIDFormatToGlobalPowerPolicy");
	powrprof.oGUIDFormatToPowerPolicy = GetProcAddress(powrprof.dll, "GUIDFormatToPowerPolicy");
	powrprof.oGetActivePwrScheme = GetProcAddress(powrprof.dll, "GetActivePwrScheme");
	powrprof.oGetCurrentPowerPolicies = GetProcAddress(powrprof.dll, "GetCurrentPowerPolicies");
	powrprof.oGetPwrCapabilities = GetProcAddress(powrprof.dll, "GetPwrCapabilities");
	powrprof.oGetPwrDiskSpindownRange = GetProcAddress(powrprof.dll, "GetPwrDiskSpindownRange");
	powrprof.oIsAdminOverrideActive = GetProcAddress(powrprof.dll, "IsAdminOverrideActive");
	powrprof.oIsPwrHibernateAllowed = GetProcAddress(powrprof.dll, "IsPwrHibernateAllowed");
	powrprof.oIsPwrShutdownAllowed = GetProcAddress(powrprof.dll, "IsPwrShutdownAllowed");
	powrprof.oIsPwrSuspendAllowed = GetProcAddress(powrprof.dll, "IsPwrSuspendAllowed");
	powrprof.oLoadCurrentPwrScheme = GetProcAddress(powrprof.dll, "LoadCurrentPwrScheme");
	powrprof.oMergeLegacyPwrScheme = GetProcAddress(powrprof.dll, "MergeLegacyPwrScheme");
	powrprof.oPowerApplyPowerRequestOverride = GetProcAddress(powrprof.dll, "PowerApplyPowerRequestOverride");
	powrprof.oPowerApplySettingChanges = GetProcAddress(powrprof.dll, "PowerApplySettingChanges");
	powrprof.oPowerCanRestoreIndividualDefaultPowerScheme = GetProcAddress(powrprof.dll, "PowerCanRestoreIndividualDefaultPowerScheme");
	powrprof.oPowerClearUserAwayPrediction = GetProcAddress(powrprof.dll, "PowerClearUserAwayPrediction");
	powrprof.oPowerCloseEnvironmentalMonitor = GetProcAddress(powrprof.dll, "PowerCloseEnvironmentalMonitor");
	powrprof.oPowerCloseLimitsMitigation = GetProcAddress(powrprof.dll, "PowerCloseLimitsMitigation");
	powrprof.oPowerCloseLimitsPolicy = GetProcAddress(powrprof.dll, "PowerCloseLimitsPolicy");
	powrprof.oPowerCreatePossibleSetting = GetProcAddress(powrprof.dll, "PowerCreatePossibleSetting");
	powrprof.oPowerCreateSetting = GetProcAddress(powrprof.dll, "PowerCreateSetting");
	powrprof.oPowerDebugDifPowerPolicies = GetProcAddress(powrprof.dll, "PowerDebugDifPowerPolicies");
	powrprof.oPowerDebugDifSystemPowerPolicies = GetProcAddress(powrprof.dll, "PowerDebugDifSystemPowerPolicies");
	powrprof.oPowerDebugDumpPowerPolicy = GetProcAddress(powrprof.dll, "PowerDebugDumpPowerPolicy");
	powrprof.oPowerDebugDumpPowerScheme = GetProcAddress(powrprof.dll, "PowerDebugDumpPowerScheme");
	powrprof.oPowerDebugDumpSystemPowerCapabilities = GetProcAddress(powrprof.dll, "PowerDebugDumpSystemPowerCapabilities");
	powrprof.oPowerDebugDumpSystemPowerPolicy = GetProcAddress(powrprof.dll, "PowerDebugDumpSystemPowerPolicy");
	powrprof.oPowerDeleteScheme = GetProcAddress(powrprof.dll, "PowerDeleteScheme");
	powrprof.oPowerDeterminePlatformRole = GetProcAddress(powrprof.dll, "PowerDeterminePlatformRole");
	powrprof.oPowerDeterminePlatformRoleEx = GetProcAddress(powrprof.dll, "PowerDeterminePlatformRoleEx");
	powrprof.oPowerDuplicateScheme = GetProcAddress(powrprof.dll, "PowerDuplicateScheme");
	powrprof.oPowerEnumerate = GetProcAddress(powrprof.dll, "PowerEnumerate");
	powrprof.oPowerGetActiveScheme = GetProcAddress(powrprof.dll, "PowerGetActiveScheme");
	powrprof.oPowerGetActualOverlayScheme = GetProcAddress(powrprof.dll, "PowerGetActualOverlayScheme");
	powrprof.oPowerGetAdaptiveStandbyDiagnostics = GetProcAddress(powrprof.dll, "PowerGetAdaptiveStandbyDiagnostics");
	powrprof.oPowerGetEffectiveOverlayScheme = GetProcAddress(powrprof.dll, "PowerGetEffectiveOverlayScheme");
	powrprof.oPowerGetOverlaySchemes = GetProcAddress(powrprof.dll, "PowerGetOverlaySchemes");
	powrprof.oPowerGetUserAwayMinPredictionConfidence = GetProcAddress(powrprof.dll, "PowerGetUserAwayMinPredictionConfidence");
	powrprof.oPowerImportPowerScheme = GetProcAddress(powrprof.dll, "PowerImportPowerScheme");
	powrprof.oPowerInformationWithPrivileges = GetProcAddress(powrprof.dll, "PowerInformationWithPrivileges");
	powrprof.oPowerIsSettingRangeDefined = GetProcAddress(powrprof.dll, "PowerIsSettingRangeDefined");
	powrprof.oPowerOpenSystemPowerKey = GetProcAddress(powrprof.dll, "PowerOpenSystemPowerKey");
	powrprof.oPowerOpenUserPowerKey = GetProcAddress(powrprof.dll, "PowerOpenUserPowerKey");
	powrprof.oPowerPolicyToGUIDFormat = GetProcAddress(powrprof.dll, "PowerPolicyToGUIDFormat");
	powrprof.oPowerReadACDefaultIndex = GetProcAddress(powrprof.dll, "PowerReadACDefaultIndex");
	powrprof.oPowerReadACValue = GetProcAddress(powrprof.dll, "PowerReadACValue");
	powrprof.oPowerReadACValueIndex = GetProcAddress(powrprof.dll, "PowerReadACValueIndex");
	powrprof.oPowerReadACValueIndexEx = GetProcAddress(powrprof.dll, "PowerReadACValueIndexEx");
	powrprof.oPowerReadDCDefaultIndex = GetProcAddress(powrprof.dll, "PowerReadDCDefaultIndex");
	powrprof.oPowerReadDCValue = GetProcAddress(powrprof.dll, "PowerReadDCValue");
	powrprof.oPowerReadDCValueIndex = GetProcAddress(powrprof.dll, "PowerReadDCValueIndex");
	powrprof.oPowerReadDCValueIndexEx = GetProcAddress(powrprof.dll, "PowerReadDCValueIndexEx");
	powrprof.oPowerReadDescription = GetProcAddress(powrprof.dll, "PowerReadDescription");
	powrprof.oPowerReadFriendlyName = GetProcAddress(powrprof.dll, "PowerReadFriendlyName");
	powrprof.oPowerReadIconResourceSpecifier = GetProcAddress(powrprof.dll, "PowerReadIconResourceSpecifier");
	powrprof.oPowerReadPossibleDescription = GetProcAddress(powrprof.dll, "PowerReadPossibleDescription");
	powrprof.oPowerReadPossibleFriendlyName = GetProcAddress(powrprof.dll, "PowerReadPossibleFriendlyName");
	powrprof.oPowerReadPossibleValue = GetProcAddress(powrprof.dll, "PowerReadPossibleValue");
	powrprof.oPowerReadSecurityDescriptor = GetProcAddress(powrprof.dll, "PowerReadSecurityDescriptor");
	powrprof.oPowerReadSettingAttributes = GetProcAddress(powrprof.dll, "PowerReadSettingAttributes");
	powrprof.oPowerReadValueIncrement = GetProcAddress(powrprof.dll, "PowerReadValueIncrement");
	powrprof.oPowerReadValueMax = GetProcAddress(powrprof.dll, "PowerReadValueMax");
	powrprof.oPowerReadValueMin = GetProcAddress(powrprof.dll, "PowerReadValueMin");
	powrprof.oPowerReadValueUnitsSpecifier = GetProcAddress(powrprof.dll, "PowerReadValueUnitsSpecifier");
	powrprof.oPowerReapplyActiveScheme = GetProcAddress(powrprof.dll, "PowerReapplyActiveScheme");
	powrprof.oPowerRegisterEnvironmentalMonitor = GetProcAddress(powrprof.dll, "PowerRegisterEnvironmentalMonitor");
	powrprof.oPowerRegisterForEffectivePowerModeNotifications = GetProcAddress(powrprof.dll, "PowerRegisterForEffectivePowerModeNotifications");
	powrprof.oPowerRegisterLimitsMitigation = GetProcAddress(powrprof.dll, "PowerRegisterLimitsMitigation");
	powrprof.oPowerRegisterLimitsPolicy = GetProcAddress(powrprof.dll, "PowerRegisterLimitsPolicy");
	powrprof.oPowerRegisterSuspendResumeNotification = GetProcAddress(powrprof.dll, "PowerRegisterSuspendResumeNotification");
	powrprof.oPowerRemovePowerSetting = GetProcAddress(powrprof.dll, "PowerRemovePowerSetting");
	powrprof.oPowerReplaceDefaultPowerSchemes = GetProcAddress(powrprof.dll, "PowerReplaceDefaultPowerSchemes");
	powrprof.oPowerReportLimitsEvent = GetProcAddress(powrprof.dll, "PowerReportLimitsEvent");
	powrprof.oPowerReportThermalEvent = GetProcAddress(powrprof.dll, "PowerReportThermalEvent");
	powrprof.oPowerRestoreACDefaultIndex = GetProcAddress(powrprof.dll, "PowerRestoreACDefaultIndex");
	powrprof.oPowerRestoreDCDefaultIndex = GetProcAddress(powrprof.dll, "PowerRestoreDCDefaultIndex");
	powrprof.oPowerRestoreDefaultPowerSchemes = GetProcAddress(powrprof.dll, "PowerRestoreDefaultPowerSchemes");
	powrprof.oPowerRestoreIndividualDefaultPowerScheme = GetProcAddress(powrprof.dll, "PowerRestoreIndividualDefaultPowerScheme");
	powrprof.oPowerSetActiveOverlayScheme = GetProcAddress(powrprof.dll, "PowerSetActiveOverlayScheme");
	powrprof.oPowerSetActiveScheme = GetProcAddress(powrprof.dll, "PowerSetActiveScheme");
	powrprof.oPowerSetAlsBrightnessOffset = GetProcAddress(powrprof.dll, "PowerSetAlsBrightnessOffset");
	powrprof.oPowerSetBrightnessAndTransitionTimes = GetProcAddress(powrprof.dll, "PowerSetBrightnessAndTransitionTimes");
	powrprof.oPowerSetUserAwayPrediction = GetProcAddress(powrprof.dll, "PowerSetUserAwayPrediction");
	powrprof.oPowerSettingAccessCheck = GetProcAddress(powrprof.dll, "PowerSettingAccessCheck");
	powrprof.oPowerSettingAccessCheckEx = GetProcAddress(powrprof.dll, "PowerSettingAccessCheckEx");
	powrprof.oPowerSettingRegisterNotification = GetProcAddress(powrprof.dll, "PowerSettingRegisterNotification");
	powrprof.oPowerSettingRegisterNotificationEx = GetProcAddress(powrprof.dll, "PowerSettingRegisterNotificationEx");
	powrprof.oPowerSettingUnregisterNotification = GetProcAddress(powrprof.dll, "PowerSettingUnregisterNotification");
	powrprof.oPowerUnregisterFromEffectivePowerModeNotifications = GetProcAddress(powrprof.dll, "PowerUnregisterFromEffectivePowerModeNotifications");
	powrprof.oPowerUnregisterSuspendResumeNotification = GetProcAddress(powrprof.dll, "PowerUnregisterSuspendResumeNotification");
	powrprof.oPowerUpdateEnvironmentalMonitorState = GetProcAddress(powrprof.dll, "PowerUpdateEnvironmentalMonitorState");
	powrprof.oPowerUpdateEnvironmentalMonitorThresholds = GetProcAddress(powrprof.dll, "PowerUpdateEnvironmentalMonitorThresholds");
	powrprof.oPowerUpdateLimitsMitigation = GetProcAddress(powrprof.dll, "PowerUpdateLimitsMitigation");
	powrprof.oPowerWriteACDefaultIndex = GetProcAddress(powrprof.dll, "PowerWriteACDefaultIndex");
	powrprof.oPowerWriteACValueIndex = GetProcAddress(powrprof.dll, "PowerWriteACValueIndex");
	powrprof.oPowerWriteDCDefaultIndex = GetProcAddress(powrprof.dll, "PowerWriteDCDefaultIndex");
	powrprof.oPowerWriteDCValueIndex = GetProcAddress(powrprof.dll, "PowerWriteDCValueIndex");
	powrprof.oPowerWriteDescription = GetProcAddress(powrprof.dll, "PowerWriteDescription");
	powrprof.oPowerWriteFriendlyName = GetProcAddress(powrprof.dll, "PowerWriteFriendlyName");
	powrprof.oPowerWriteIconResourceSpecifier = GetProcAddress(powrprof.dll, "PowerWriteIconResourceSpecifier");
	powrprof.oPowerWritePossibleDescription = GetProcAddress(powrprof.dll, "PowerWritePossibleDescription");
	powrprof.oPowerWritePossibleFriendlyName = GetProcAddress(powrprof.dll, "PowerWritePossibleFriendlyName");
	powrprof.oPowerWritePossibleValue = GetProcAddress(powrprof.dll, "PowerWritePossibleValue");
	powrprof.oPowerWriteSecurityDescriptor = GetProcAddress(powrprof.dll, "PowerWriteSecurityDescriptor");
	powrprof.oPowerWriteSettingAttributes = GetProcAddress(powrprof.dll, "PowerWriteSettingAttributes");
	powrprof.oPowerWriteValueIncrement = GetProcAddress(powrprof.dll, "PowerWriteValueIncrement");
	powrprof.oPowerWriteValueMax = GetProcAddress(powrprof.dll, "PowerWriteValueMax");
	powrprof.oPowerWriteValueMin = GetProcAddress(powrprof.dll, "PowerWriteValueMin");
	powrprof.oPowerWriteValueUnitsSpecifier = GetProcAddress(powrprof.dll, "PowerWriteValueUnitsSpecifier");
	powrprof.oReadGlobalPwrPolicy = GetProcAddress(powrprof.dll, "ReadGlobalPwrPolicy");
	powrprof.oReadProcessorPwrScheme = GetProcAddress(powrprof.dll, "ReadProcessorPwrScheme");
	powrprof.oReadPwrScheme = GetProcAddress(powrprof.dll, "ReadPwrScheme");
	powrprof.oSetActivePwrScheme = GetProcAddress(powrprof.dll, "SetActivePwrScheme");
	powrprof.oSetSuspendState = GetProcAddress(powrprof.dll, "SetSuspendState");
	powrprof.oValidatePowerPolicies = GetProcAddress(powrprof.dll, "ValidatePowerPolicies");
	powrprof.oWriteGlobalPwrPolicy = GetProcAddress(powrprof.dll, "WriteGlobalPwrPolicy");
	powrprof.oWriteProcessorPwrScheme = GetProcAddress(powrprof.dll, "WriteProcessorPwrScheme");
	powrprof.oWritePwrScheme = GetProcAddress(powrprof.dll, "WritePwrScheme");
}
#pragma endregion

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		char path[MAX_PATH];
		GetWindowsDirectory(path, sizeof(path));

		strcat_s(path, "\\System32\\powrprof.dll");
		powrprof.dll = LoadLibrary(path);
		setupFunctions();
		module = hModule;

		//CreateThread(nullptr, 0, main, hModule, 0, nullptr);
		main(nullptr);

		break;
	case DLL_PROCESS_DETACH:
		FreeLibrary(powrprof.dll);
		break;
	}
	return 1;
}
