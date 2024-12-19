//
// Copyright (C) 2024 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "nfa_dm_api.cc"

#ifdef NFA_STATUS_FAILED
#undef NFA_STATUS_FAILED
#endif
#define NFA_STATUS_FAILED 0x00

class MockGKI {
public:
    MOCK_METHOD(void*, getbuf, (uint16_t size), ());
    MOCK_METHOD(void, freebuf, (void* p_buf), ());
};
class MockNfaSys {
public:
    MOCK_METHOD(void, sendmsg, (void* p_msg), ());
};
class NFAInitMock {
public:
    MOCK_METHOD(void, nfa_sys_init, (), ());
    MOCK_METHOD(void, nfa_dm_init, (), ());
    MOCK_METHOD(void, nfa_ee_init, (), ());
    MOCK_METHOD(void, NFC_Init, (tHAL_NFC_ENTRY*), ());
    MOCK_METHOD(void, NFA_SetNfccMode, (uint8_t), ());
};

class NFADeactivateTest : public ::testing::Test {
protected:
    static MockGKI mock_gki;
    static MockNfaSys mock_nfa_sys;
    void SetUp() override {
    }
    void TearDown() override {
        testing::Mock::AllowLeak(reinterpret_cast<const void*>(&mock_gki));
        testing::Mock::AllowLeak(reinterpret_cast<const void*>(&mock_nfa_sys));


    }
};

MockGKI NFADeactivateTest::mock_gki;
MockNfaSys NFADeactivateTest::mock_nfa_sys;
TEST_F(NFADeactivateTest, Deactivate_SleepMode_Success) {
    bool sleep_mode = true;
    EXPECT_CALL(mock_gki, getbuf(sizeof(tNFA_DM_API_DEACTIVATE))).WillOnce(
            testing::Invoke([=]() -> void* {
                auto* mock_msg = new tNFA_DM_API_DEACTIVATE();
                mock_msg->hdr.event = NFA_DM_API_DEACTIVATE_EVT;
                mock_msg->sleep_mode = sleep_mode;
                return mock_msg;
            }));
    EXPECT_CALL(mock_nfa_sys, sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_Deactivate(sleep_mode);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NFADeactivateTest, Deactivate_NonSleepMode_Success) {
    bool sleep_mode = false;
    EXPECT_CALL(mock_gki, getbuf(sizeof(tNFA_DM_API_DEACTIVATE))).WillOnce(
            testing::Invoke([=]() -> void* {
                auto* mock_msg = new tNFA_DM_API_DEACTIVATE();
                mock_msg->hdr.event = NFA_DM_API_DEACTIVATE_EVT;
                mock_msg->sleep_mode = sleep_mode;
                return mock_msg;
            }));
    EXPECT_CALL(mock_nfa_sys, sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_Deactivate(sleep_mode);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NFADeactivateTest, Deactivate_BufferAllocationFailure) {
    bool sleep_mode = true;
    EXPECT_CALL(mock_gki, getbuf(sizeof(tNFA_DM_API_DEACTIVATE))).WillOnce(
            testing::Return(nullptr));
    tNFA_STATUS result = NFA_Deactivate(sleep_mode);
    EXPECT_EQ(result, NFA_STATUS_FAILED);
}

TEST_F(NFADeactivateTest, Deactivate_MultipleRequests) {
    auto* mock_msg1 = new tNFA_DM_API_DEACTIVATE();
    auto* mock_msg2 = new tNFA_DM_API_DEACTIVATE();
    EXPECT_CALL(mock_gki, getbuf(sizeof(tNFA_DM_API_DEACTIVATE))).WillOnce(
            testing::Return(mock_msg1)).WillOnce(
                    testing::Return(mock_msg2));
    EXPECT_CALL(mock_nfa_sys, sendmsg(mock_msg1)).Times(1);
    EXPECT_CALL(mock_nfa_sys, sendmsg(mock_msg2)).Times(1);
    EXPECT_EQ(NFA_Deactivate(true), NFA_STATUS_OK);
    EXPECT_EQ(NFA_Deactivate(false), NFA_STATUS_OK);
}

TEST_F(NFADeactivateTest, Deactivate_BufferFailureStressTest) {
    EXPECT_CALL(mock_gki, getbuf(sizeof(tNFA_DM_API_DEACTIVATE))).WillRepeatedly(
            testing::Return(nullptr));
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(NFA_Deactivate(true), NFA_STATUS_FAILED);
        EXPECT_EQ(NFA_Deactivate(false), NFA_STATUS_FAILED);
    }
}

//tests for NFA_DeregisterNDefTypeHandler()

TEST_F(NFADeactivateTest, Deregistration_Success) {
    tNFA_HANDLE ndef_type_handle = 1;
    tNFA_DM_API_DEREG_NDEF_HDLR mock_msg = {};
    EXPECT_CALL(mock_gki, getbuf(sizeof(tNFA_DM_API_DEREG_NDEF_HDLR))).WillOnce(
            testing::Return(&mock_msg));
    mock_msg.hdr.event = NFA_DM_API_DEREG_NDEF_HDLR_EVT;
    mock_msg.ndef_type_handle = ndef_type_handle;
    EXPECT_CALL(mock_nfa_sys, sendmsg(&mock_msg)).Times(1);
    tNFA_STATUS result = NFA_DeregisterNDefTypeHandler(ndef_type_handle);
    EXPECT_EQ(result, NFA_STATUS_OK);
    EXPECT_EQ(mock_msg.hdr.event, NFA_DM_API_DEREG_NDEF_HDLR_EVT);
    EXPECT_EQ(mock_msg.ndef_type_handle, ndef_type_handle);
}

TEST_F(NFADeactivateTest, Deregistration_BufferAllocationFailure) {
    tNFA_HANDLE ndef_type_handle = 0x02;
    EXPECT_CALL(mock_gki, getbuf(sizeof(tNFA_DM_API_DEREG_NDEF_HDLR))).WillOnce(
            testing::Return(nullptr));
    tNFA_STATUS result = NFA_DeregisterNDefTypeHandler(ndef_type_handle);
    EXPECT_EQ(result, NFA_STATUS_FAILED);
}

TEST_F(NFADeactivateTest, Deregistration_EventAssignment) {
    tNFA_HANDLE ndef_type_handle = 1;
    tNFA_DM_API_DEREG_NDEF_HDLR mock_msg = {};
    EXPECT_CALL(mock_gki, getbuf(sizeof(tNFA_DM_API_DEREG_NDEF_HDLR))).WillOnce(
            testing::Return(&mock_msg));
    mock_msg.hdr.event = NFA_DM_API_DEREG_NDEF_HDLR_EVT;
    mock_msg.ndef_type_handle = ndef_type_handle;
    EXPECT_CALL(mock_nfa_sys, sendmsg(&mock_msg)).Times(1);
    tNFA_STATUS result = NFA_DeregisterNDefTypeHandler(ndef_type_handle);
    EXPECT_EQ(result, NFA_STATUS_OK);
    EXPECT_EQ(mock_msg.hdr.event, NFA_DM_API_DEREG_NDEF_HDLR_EVT);
    EXPECT_EQ(mock_msg.ndef_type_handle, ndef_type_handle);
}

TEST_F(NFADeactivateTest, Deregistration_LargeHandle) {
    tNFA_HANDLE ndef_type_handle = 0xFFFF;
    tNFA_DM_API_DEREG_NDEF_HDLR mock_msg = {};
    EXPECT_CALL(mock_gki, getbuf(sizeof(
            tNFA_DM_API_DEREG_NDEF_HDLR))).WillOnce(testing::Return(&mock_msg));
    mock_msg.hdr.event = NFA_DM_API_DEREG_NDEF_HDLR_EVT;
    mock_msg.ndef_type_handle = ndef_type_handle;
    EXPECT_CALL(mock_nfa_sys, sendmsg(&mock_msg)).Times(1);
    tNFA_STATUS result = NFA_DeregisterNDefTypeHandler(ndef_type_handle);
    EXPECT_EQ(result, NFA_STATUS_OK);
    EXPECT_EQ(mock_msg.hdr.event, NFA_DM_API_DEREG_NDEF_HDLR_EVT);
    EXPECT_EQ(mock_msg.ndef_type_handle, ndef_type_handle);
}

class NFA_DisableDtamodeTest : public testing::Test {
protected:
    void SetUp() override {
        appl_dta_mode_flag = 0xFF;
        nfa_dm_cb.eDtaMode = 0x00;
    }
    void TearDown() override {
    }
};

TEST_F(NFA_DisableDtamodeTest, DisablesDtaModeFlag) {
    NFA_DisableDtamode();
    EXPECT_EQ(appl_dta_mode_flag, 0x0);
}

TEST_F(NFA_DisableDtamodeTest, DisablesDtaModeInCb) {
    NFA_DisableDtamode();
    EXPECT_EQ(nfa_dm_cb.eDtaMode, NFA_DTA_APPL_MODE);
}

TEST_F(NFA_DisableDtamodeTest, UpdatesBothFlagAndMode) {
    appl_dta_mode_flag = 0xAA;
    nfa_dm_cb.eDtaMode = 0xFF;
    NFA_DisableDtamode();
    EXPECT_EQ(appl_dta_mode_flag, 0x0);
    EXPECT_EQ(nfa_dm_cb.eDtaMode, NFA_DTA_APPL_MODE);
}

TEST_F(NFA_DisableDtamodeTest, NoChangeIfFlagIsAlreadyZero) {
    appl_dta_mode_flag = 0x0;
    uint8_t previous_mode = nfa_dm_cb.eDtaMode;
    NFA_DisableDtamode();
    EXPECT_EQ(appl_dta_mode_flag, 0x0);
    EXPECT_EQ(previous_mode, nfa_dm_cb.eDtaMode);
}

class NFA_EnableDtamodeTest : public testing::Test {
protected:
    void SetUp() override {
        appl_dta_mode_flag = 0x0;
    }
    void TearDown() override {
    }
};

TEST_F(NFA_EnableDtamodeTest, SetToApplMode) {
    NFA_EnableDtamode(NFA_DTA_APPL_MODE);
    EXPECT_EQ(nfa_dm_cb.eDtaMode, NFA_DTA_APPL_MODE);
    EXPECT_EQ(appl_dta_mode_flag, 0x01);
}

TEST_F(NFA_EnableDtamodeTest, SetToDefaultMode) {
    NFA_EnableDtamode(NFA_DTA_DEFAULT_MODE);
    EXPECT_EQ(nfa_dm_cb.eDtaMode, NFA_DTA_DEFAULT_MODE);
    EXPECT_EQ(appl_dta_mode_flag, 0x01);
}

TEST_F(NFA_EnableDtamodeTest, SetToLlcpMode) {
    NFA_EnableDtamode(NFA_DTA_LLCP_MODE);
    EXPECT_EQ(nfa_dm_cb.eDtaMode, NFA_DTA_LLCP_MODE);
    EXPECT_EQ(appl_dta_mode_flag, 0x01);
}

TEST_F(NFA_EnableDtamodeTest, SetToHcefMode) {
    NFA_EnableDtamode(NFA_DTA_HCEF_MODE);
    EXPECT_EQ(nfa_dm_cb.eDtaMode, NFA_DTA_HCEF_MODE);
    EXPECT_EQ(appl_dta_mode_flag, 0x01);
}

TEST_F(NFA_EnableDtamodeTest, SetToCr8Mode) {
    NFA_EnableDtamode(NFA_DTA_CR8);
    EXPECT_EQ(nfa_dm_cb.eDtaMode, NFA_DTA_CR8);
    EXPECT_EQ(appl_dta_mode_flag, 0x01);
}

TEST_F(NFA_EnableDtamodeTest, MultipleModeChanges) {
    NFA_EnableDtamode(NFA_DTA_APPL_MODE);
    EXPECT_EQ(nfa_dm_cb.eDtaMode, NFA_DTA_APPL_MODE);
    NFA_EnableDtamode(NFA_DTA_LLCP_MODE);
    EXPECT_EQ(nfa_dm_cb.eDtaMode, NFA_DTA_LLCP_MODE);
}

TEST_F(NFA_EnableDtamodeTest, SameModeTwice) {
    NFA_EnableDtamode(NFA_DTA_HCEF_MODE);
    EXPECT_EQ(nfa_dm_cb.eDtaMode, NFA_DTA_HCEF_MODE);
    NFA_EnableDtamode(NFA_DTA_HCEF_MODE);
    EXPECT_EQ(nfa_dm_cb.eDtaMode, NFA_DTA_HCEF_MODE);
}

class NFA_Power_Mock {
public:
    MOCK_METHOD(NFC_HDR*, GKI_getbuf, (size_t size), ());
    MOCK_METHOD(void, nfa_sys_sendmsg, (NFC_HDR* p_msg), ());
};

class NFA_PowerOffSleepMode_Test : public ::testing::Test {
protected:
    static NFA_Power_Mock nfa_power_mock;
    void SetUp() override {
        nfa_dm_cb.flags = 0;
    }
    void TearDown() override {
        testing::Mock::AllowLeak(reinterpret_cast<const void*>(&nfa_power_mock));
    }
};

NFA_Power_Mock NFA_PowerOffSleepMode_Test::nfa_power_mock;
TEST_F(NFA_PowerOffSleepMode_Test, EnteringPowerOffSleepMode) {
    EXPECT_CALL(nfa_power_mock, GKI_getbuf(
            sizeof(NFC_HDR))).WillOnce(testing::Return(new NFC_HDR()));
    EXPECT_CALL(nfa_power_mock, nfa_sys_sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_PowerOffSleepMode(true);
    EXPECT_EQ(result, NFA_STATUS_OK);
    EXPECT_EQ(nfa_dm_cb.flags & NFA_DM_FLAGS_SETTING_PWR_MODE, NFA_DM_FLAGS_SETTING_PWR_MODE);
}

TEST_F(NFA_PowerOffSleepMode_Test, LeavingPowerOffSleepMode) {
    EXPECT_CALL(nfa_power_mock, GKI_getbuf(sizeof(NFC_HDR))).WillOnce(
            testing::Return(new NFC_HDR()));
    EXPECT_CALL(nfa_power_mock, nfa_sys_sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_PowerOffSleepMode(false);
    EXPECT_EQ(result, NFA_STATUS_OK);
    EXPECT_EQ(nfa_dm_cb.flags & NFA_DM_FLAGS_SETTING_PWR_MODE, NFA_DM_FLAGS_SETTING_PWR_MODE);
}

TEST_F(NFA_PowerOffSleepMode_Test, FailureDueToBufferAllocationFailure) {
    EXPECT_CALL(nfa_power_mock, GKI_getbuf(sizeof(NFC_HDR))).WillOnce(
            testing::Return(nullptr));
    EXPECT_CALL(nfa_power_mock, nfa_sys_sendmsg(testing::_)).Times(0);
    tNFA_STATUS result = NFA_PowerOffSleepMode(true);
    EXPECT_EQ(result, NFA_STATUS_FAILED);
}

class MockNfaRegister {
public:
    MOCK_METHOD(void*, GKI_getbuf, (uint16_t size), ());
    MOCK_METHOD(void, nfa_sys_sendmsg, (tNFA_DM_API_REG_NDEF_HDLR* p_msg), ());
};

void mock_callback(unsigned char, tNFA_NDEF_EVT_DATA* p_data) {
    (void)p_data;
}
class NfaRegisterNDefUriHandlerTest : public ::testing::Test {
protected:
    static MockNfaRegister mock_nfa_register;
    void SetUp() override {
    }
    void TearDown() override {
        testing::Mock::AllowLeak(reinterpret_cast<const void*>(&mock_nfa_register));

    }
};

MockNfaRegister NfaRegisterNDefUriHandlerTest::mock_nfa_register;
TEST_F(NfaRegisterNDefUriHandlerTest, ValidParameters) {
    uint8_t uri[] = "tel:";
    uint8_t uri_len = sizeof(uri) - 1;
    tNFA_DM_API_REG_NDEF_HDLR expected_msg = {};
    expected_msg.flags = NFA_NDEF_FLAGS_WKT_URI;
    expected_msg.tnf = NFA_TNF_WKT;
    expected_msg.uri_id = NFA_NDEF_URI_ID_ABSOLUTE;
    expected_msg.name_len = uri_len;
    memcpy(expected_msg.name, uri, uri_len);
    expected_msg.p_ndef_cback = &mock_callback;
    EXPECT_CALL(mock_nfa_register, GKI_getbuf(
            testing::_)).WillOnce(testing::Return(&expected_msg));
    EXPECT_CALL(mock_nfa_register, nfa_sys_sendmsg(&expected_msg)).Times(1);
    EXPECT_EQ(NFA_RegisterNDefUriHandler(
            true, NFA_NDEF_URI_ID_ABSOLUTE,
            uri, uri_len, mock_callback), NFA_STATUS_OK);
}

TEST_F(NfaRegisterNDefUriHandlerTest, NullCallback) {
    EXPECT_EQ(NFA_RegisterNDefUriHandler(
            true, NFA_NDEF_URI_ID_ABSOLUTE,
            nullptr, 0, nullptr), NFA_STATUS_INVALID_PARAM);
}

TEST_F(NfaRegisterNDefUriHandlerTest, MemoryAllocationFailure) {
    uint8_t uri[] = "http://example.com";
    uint8_t uri_len = sizeof(uri) - 1;
    EXPECT_CALL(mock_nfa_register, GKI_getbuf(
            testing::_)).WillOnce(testing::Return(nullptr));
    EXPECT_EQ(NFA_RegisterNDefUriHandler(
            true, NFA_NDEF_URI_ID_ABSOLUTE,
            uri, uri_len, mock_callback), NFA_STATUS_FAILED);
}

TEST_F(NfaRegisterNDefUriHandlerTest, InvalidUriId) {
    uint8_t uri[] = "tel:";
    uint8_t uri_len = sizeof(uri) - 1;
    tNFA_DM_API_REG_NDEF_HDLR expected_msg = {};
    expected_msg.flags = NFA_NDEF_FLAGS_WKT_URI;
    expected_msg.tnf = NFA_TNF_WKT;
    expected_msg.uri_id = NFA_NDEF_URI_ID_HTTP;
    expected_msg.name_len = 0;
    expected_msg.p_ndef_cback = &mock_callback;
    EXPECT_CALL(mock_nfa_register, GKI_getbuf(
            testing::_)).WillOnce(testing::Return(&expected_msg));
    EXPECT_CALL(mock_nfa_register, nfa_sys_sendmsg(&expected_msg)).Times(1);
    EXPECT_EQ(NFA_RegisterNDefUriHandler(
            true, NFA_NDEF_URI_ID_HTTP, uri,
            uri_len, &mock_callback), NFA_STATUS_OK);
}

class MockNfaRelease {
public:
    MOCK_METHOD(void*, GKI_getbuf, (uint16_t size), ());
    MOCK_METHOD(void, nfa_sys_sendmsg, (NFC_HDR * p_msg), ());
};

class NfaReleaseExclusiveRfControlTest : public testing::Test {
protected:
    static MockNfaRelease mock_nfa_release;
    void SetUp() override {
        nfa_dm_cb.p_excl_conn_cback = nullptr;
    }
    void TearDown() override {
        testing::Mock::AllowLeak(reinterpret_cast<const void*>(&mock_nfa_release));

    }
};
MockNfaRelease NfaReleaseExclusiveRfControlTest::mock_nfa_release;
TEST_F(NfaReleaseExclusiveRfControlTest, Test_MemoryAllocationFailure) {
    nfa_dm_cb.p_excl_conn_cback = reinterpret_cast<tNFA_CONN_CBACK*>(0x1234);
    EXPECT_CALL(mock_nfa_release, GKI_getbuf(testing::_)).WillOnce(
            testing::Return(nullptr));
    EXPECT_EQ(NFA_ReleaseExclusiveRfControl(), NFA_STATUS_FAILED);
}

TEST_F(NfaReleaseExclusiveRfControlTest, Test_Success) {
    nfa_dm_cb.p_excl_conn_cback = reinterpret_cast<tNFA_CONN_CBACK*>(0x1234);
    NFC_HDR mock_msg;
    EXPECT_CALL(mock_nfa_release, GKI_getbuf(testing::_)).WillOnce(
            testing::Return(&mock_msg));
    EXPECT_CALL(mock_nfa_release, nfa_sys_sendmsg(&mock_msg)).Times(1);
    EXPECT_EQ(NFA_ReleaseExclusiveRfControl(), NFA_STATUS_OK);
}

TEST_F(NfaReleaseExclusiveRfControlTest, Test_ValidCallback) {
    nfa_dm_cb.p_excl_conn_cback = reinterpret_cast<tNFA_CONN_CBACK*>(0x1234);
    NFC_HDR mock_msg;
    EXPECT_CALL(mock_nfa_release, GKI_getbuf(testing::_)).WillOnce(
            testing::Return(&mock_msg));
    EXPECT_CALL(mock_nfa_release, nfa_sys_sendmsg(&mock_msg)).Times(1);
    EXPECT_EQ(NFA_ReleaseExclusiveRfControl(), NFA_STATUS_OK);
}

class MockNfaSelect {
public:
    MOCK_METHOD(NFC_HDR*, GKI_getbuf, (uint16_t size), ());
    MOCK_METHOD(void, nfa_sys_sendmsg, (NFC_HDR* p_msg), ());
};

class NfaSelectTest : public testing::Test {
protected:
    static MockNfaSelect mock_nfa;
    void SetUp() override {
    }
    void TearDown() override {
        testing::Mock::AllowLeak(reinterpret_cast<const void*>(&mock_nfa));

    }
};

MockNfaSelect NfaSelectTest::mock_nfa;
TEST_F(NfaSelectTest, TestSuccessfulSelection) {
    uint8_t rf_disc_id = 0x01;
    tNFA_NFC_PROTOCOL protocol = NFA_PROTOCOL_ISO_DEP;
    tNFA_INTF_TYPE rf_interface = NFA_INTERFACE_ISO_DEP;
    NFC_HDR mock_msg;
    EXPECT_CALL(mock_nfa, GKI_getbuf(testing::_)).WillOnce(
            testing::Return(&mock_msg));
    EXPECT_CALL(mock_nfa, nfa_sys_sendmsg(&mock_msg)).Times(1);
    EXPECT_EQ(NFA_Select(rf_disc_id, protocol, rf_interface), NFA_STATUS_OK);
}

TEST_F(NfaSelectTest, TestInvalidProtocolForIsoDepInterface) {
    uint8_t rf_disc_id = 0x01;
    tNFA_NFC_PROTOCOL protocol = static_cast<tNFA_NFC_PROTOCOL>(0);
    tNFA_INTF_TYPE rf_interface = NFA_INTERFACE_ISO_DEP;
    EXPECT_EQ(NFA_Select(rf_disc_id, protocol, rf_interface), NFA_STATUS_INVALID_PARAM);
}

TEST_F(NfaSelectTest, TestMemoryAllocationFailure) {
    uint8_t rf_disc_id = 0x01;
    tNFA_NFC_PROTOCOL protocol = NFA_PROTOCOL_ISO_DEP;
    tNFA_INTF_TYPE rf_interface = NFA_INTERFACE_ISO_DEP;
    EXPECT_CALL(mock_nfa, GKI_getbuf(testing::_)).WillOnce(
            testing::Return(nullptr));
    EXPECT_EQ(NFA_Select(rf_disc_id, protocol, rf_interface), NFA_STATUS_FAILED);
}

class MockNfaSend {
public:
    MOCK_METHOD(void*, getbuf, (uint16_t size), (const));
};

class NfaSendRawFrameTest : public testing::Test {
protected:
    static MockNfaSend mock_nfa_send;
    void SetUp() override {
    }

    void TearDown() override {
        testing::Mock::AllowLeak(reinterpret_cast<const void*>(&mock_nfa_send));

    }
};
MockNfaSend NfaSendRawFrameTest::mock_nfa_send;
TEST_F(NfaSendRawFrameTest, TestValidData) {
    uint8_t raw_data[] = {0x01, 0x02, 0x03};
    uint16_t data_len = sizeof(raw_data);
    uint16_t presence_check_start_delay = 10;
    EXPECT_CALL(mock_nfa_send, getbuf(testing::_))
            .WillOnce(testing::Return(new NFC_HDR()));
    tNFA_STATUS result = NFA_SendRawFrame(raw_data, data_len, presence_check_start_delay);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NfaSendRawFrameTest, TestNullDataPointer) {
    uint8_t* raw_data = nullptr;
    uint16_t data_len = 5;
    uint16_t presence_check_start_delay = 10;
    EXPECT_CALL(mock_nfa_send, getbuf(testing::_))
            .WillOnce(testing::Return(new NFC_HDR()));
    tNFA_STATUS result = NFA_SendRawFrame(raw_data, data_len, presence_check_start_delay);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NfaSendRawFrameTest, TestZeroLengthData) {
    uint8_t* raw_data = nullptr;
    uint16_t data_len = 0;
    uint16_t presence_check_start_delay = 10;
    EXPECT_CALL(mock_nfa_send, getbuf(testing::_))
            .WillOnce(testing::Return(new NFC_HDR()));
    tNFA_STATUS result = NFA_SendRawFrame(raw_data, data_len, presence_check_start_delay);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NfaSendRawFrameTest, TestMemoryAllocationFailure) {
    uint8_t raw_data[] = {0x01, 0x02, 0x03};
    uint16_t data_len = sizeof(raw_data);
    uint16_t presence_check_start_delay = 10;
    EXPECT_CALL(mock_nfa_send, getbuf(testing::_))
            .WillOnce(testing::Return(nullptr));
    tNFA_STATUS result = NFA_SendRawFrame(raw_data, data_len, presence_check_start_delay);
    EXPECT_EQ(result, NFA_STATUS_FAILED);
}

class NfaSetNfccModeTest : public testing::Test {
protected:
    void SetUp() override {
        nfc_cb.nfcc_mode = 0;
    }
};

TEST_F(NfaSetNfccModeTest, TestSetModeToDefault) {
    uint8_t mode = ENABLE_MODE_DEFAULT;
    nfc_cb.nfcc_mode = ENABLE_MODE_TRANSPARENT;
    NFA_SetNfccMode(mode);
    EXPECT_EQ(nfc_cb.nfcc_mode, mode);
}

TEST_F(NfaSetNfccModeTest, TestSetModeToTransparent) {
    uint8_t mode = ENABLE_MODE_TRANSPARENT;
    nfc_cb.nfcc_mode = ENABLE_MODE_DEFAULT;
    NFA_SetNfccMode(mode);
    EXPECT_EQ(nfc_cb.nfcc_mode, mode);
}

TEST_F(NfaSetNfccModeTest, TestSetModeToEE) {
    uint8_t mode = ENABLE_MODE_EE;
    nfc_cb.nfcc_mode = ENABLE_MODE_DEFAULT;
    NFA_SetNfccMode(mode);
    EXPECT_EQ(nfc_cb.nfcc_mode, mode);
}

TEST_F(NfaSetNfccModeTest, TestRedundantModeChange) {
    uint8_t mode = ENABLE_MODE_TRANSPARENT;
    nfc_cb.nfcc_mode = mode;
    NFA_SetNfccMode(mode);
    EXPECT_EQ(nfc_cb.nfcc_mode, mode);
}

class MockNfaSVC {
public:
    MOCK_METHOD(void, nfa_sys_sendmsg, (void* p_msg), ());
};

class NFA_SendVsCommand_Test : public ::testing::Test {
protected:
    static MockNfaSVC mock_nfa_svc;
    void SetUp() override {
    }

    void TearDown() override {
    }
};

MockNfaSVC NFA_SendVsCommand_Test::mock_nfa_svc;
TEST_F(NFA_SendVsCommand_Test, TestValidCommand) {
    uint8_t oid = 0x01;
    uint8_t cmd_params_len = 4;
    uint8_t cmd_params[] = {0x11, 0x22, 0x33, 0x44};
    tNFA_VSC_CBACK* p_cback = nullptr;
    EXPECT_CALL(mock_nfa_svc, nfa_sys_sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_SendVsCommand(oid, cmd_params_len, cmd_params, p_cback);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NFA_SendVsCommand_Test, TestValidCommandWithNullParams) {
    uint8_t oid = 0x02;
    uint8_t cmd_params_len = 0;
    uint8_t* cmd_params = nullptr;
    tNFA_VSC_CBACK* p_cback = nullptr;
    EXPECT_CALL(mock_nfa_svc, nfa_sys_sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_SendVsCommand(oid, cmd_params_len, cmd_params, p_cback);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NFA_SendVsCommand_Test, TestNullCmdParamsWithZeroLength) {
    uint8_t oid = 0x03;
    uint8_t cmd_params_len = 0;
    uint8_t* cmd_params = nullptr;
    tNFA_VSC_CBACK* p_cback = nullptr;
    EXPECT_CALL(mock_nfa_svc, nfa_sys_sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_SendVsCommand(oid, cmd_params_len, cmd_params, p_cback);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NFA_SendVsCommand_Test, TestInvalidCmdParamsLength) {
    uint8_t oid = 0x04;
    uint8_t cmd_params_len = 255;
    uint8_t cmd_params[255] = {};
    tNFA_VSC_CBACK* p_cback = nullptr;
    EXPECT_CALL(mock_nfa_svc, nfa_sys_sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_SendVsCommand(oid, cmd_params_len, cmd_params, p_cback);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NFA_SendVsCommand_Test, TestMemoryAllocationFailure) {
    uint8_t oid = 0x05;
    uint8_t cmd_params_len = 4;
    uint8_t cmd_params[] = {0x01, 0x02, 0x03, 0x04};
    tNFA_VSC_CBACK* p_cback = nullptr;
    EXPECT_CALL(mock_nfa_svc, nfa_sys_sendmsg(testing::_)).Times(0);
    tNFA_STATUS result = NFA_SendVsCommand(oid, cmd_params_len, cmd_params, p_cback);
    EXPECT_EQ(result, NFA_STATUS_FAILED);
}

TEST_F(NFA_SendVsCommand_Test, TestInvalidOID) {
    uint8_t oid = 0xFF;
    uint8_t cmd_params_len = 3;
    uint8_t cmd_params[] = {0x01, 0x02, 0x03};
    tNFA_VSC_CBACK* p_cback = nullptr;
    EXPECT_CALL(mock_nfa_svc, nfa_sys_sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_SendVsCommand(oid, cmd_params_len, cmd_params, p_cback);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NFA_SendVsCommand_Test, TestNullCallback) {
    uint8_t oid = 0x06;
    uint8_t cmd_params_len = 4;
    uint8_t cmd_params[] = {0x11, 0x22, 0x33, 0x44};
    tNFA_VSC_CBACK* p_cback = nullptr;
    EXPECT_CALL(mock_nfa_svc, nfa_sys_sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_SendVsCommand(oid, cmd_params_len, cmd_params, p_cback);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

#define INVALID_RF_TECH_MODE 0xFF
#define INVALID_BIT_RATE     0xFF
class MockNfaUpdate {
public:
    MOCK_METHOD(void, nfa_sys_sendmsg, (void* p_msg), ());
};

class NFA_UpdateRFCommParams_Test : public ::testing::Test {
protected:
    static MockNfaUpdate mock_nfa_update;
    void SetUp() override {
    }
    void TearDown() override {
    }
};

MockNfaUpdate NFA_UpdateRFCommParams_Test::mock_nfa_update;
TEST_F(NFA_UpdateRFCommParams_Test, TestDefaultValidParams) {
    tNFC_RF_COMM_PARAMS rf_params = {
            .include_rf_tech_mode = true,
            .rf_tech_n_mode = NCI_DISCOVERY_TYPE_POLL_A,
            .include_tx_bit_rate = true,
            .tx_bit_rate = NCI_BIT_RATE_212 ,
            .include_rx_bit_rate = true,
            .rx_bit_rate = NCI_BIT_RATE_212 ,
            .include_nfc_b_config = false,
            .min_tr0 = 10,
            .min_tr1 = 20,
            .suppression_eos = 0,
            .suppression_sos = 0,
            .min_tr2 = 30
    };
    EXPECT_CALL(mock_nfa_update, nfa_sys_sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_UpdateRFCommParams(&rf_params);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NFA_UpdateRFCommParams_Test, TestAllFlagsTrue) {
    tNFC_RF_COMM_PARAMS rf_params = {
            .include_rf_tech_mode = true,
            .rf_tech_n_mode = NCI_DISCOVERY_TYPE_POLL_B_PRIME,
            .include_tx_bit_rate = true,
            .tx_bit_rate = NCI_BIT_RATE_424,
            .include_rx_bit_rate = true,
            .rx_bit_rate = NCI_BIT_RATE_424,
            .include_nfc_b_config = true,
            .min_tr0 = 15,
            .min_tr1 = 25,
            .suppression_eos = 1,
            .suppression_sos = 1,
            .min_tr2 = 35
    };
    EXPECT_CALL(mock_nfa_update, nfa_sys_sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_UpdateRFCommParams(&rf_params);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NFA_UpdateRFCommParams_Test, TestMissingOptionalParams) {
    tNFC_RF_COMM_PARAMS rf_params = {
            .include_rf_tech_mode = false,
            .rf_tech_n_mode = NCI_DISCOVERY_TYPE_POLL_A,
            .include_tx_bit_rate = false,
            .tx_bit_rate = NCI_BIT_RATE_212,
            .include_rx_bit_rate = false,
            .rx_bit_rate = NCI_BIT_RATE_212,
            .include_nfc_b_config = false,
            .min_tr0 = 10,
            .min_tr1 = 20,
            .suppression_eos = 0,
            .suppression_sos = 0,
            .min_tr2 = 30
    };
    EXPECT_CALL(mock_nfa_update, nfa_sys_sendmsg(testing::_)).Times(1);
    tNFA_STATUS result = NFA_UpdateRFCommParams(&rf_params);
    EXPECT_EQ(result, NFA_STATUS_OK);
}

TEST_F(NFA_UpdateRFCommParams_Test, TestInvalidRfTechMode) {
    tNFC_RF_COMM_PARAMS rf_params = {
            .include_rf_tech_mode = true,
            .rf_tech_n_mode = INVALID_RF_TECH_MODE,
            .include_tx_bit_rate = true,
            .tx_bit_rate = NCI_BIT_RATE_212,
            .include_rx_bit_rate = true,
            .rx_bit_rate = NCI_BIT_RATE_212,
            .include_nfc_b_config = false,
            .min_tr0 = 10,
            .min_tr1 = 20,
            .suppression_eos = 0,
            .suppression_sos = 0,
            .min_tr2 = 30
    };
    EXPECT_CALL(mock_nfa_update, nfa_sys_sendmsg(testing::_)).Times(0);
    tNFA_STATUS result = NFA_UpdateRFCommParams(&rf_params);
    EXPECT_EQ(result, NFA_STATUS_FAILED);
}

TEST_F(NFA_UpdateRFCommParams_Test, TestInvalidBitRate) {
    tNFC_RF_COMM_PARAMS rf_params = {
            .include_rf_tech_mode = true,
            .rf_tech_n_mode = NCI_DISCOVERY_TYPE_POLL_A,
            .include_tx_bit_rate = true,
            .tx_bit_rate = INVALID_BIT_RATE,
            .include_rx_bit_rate = true,
            .rx_bit_rate = INVALID_BIT_RATE,
            .include_nfc_b_config = false,
            .min_tr0 = 10,
            .min_tr1 = 20,
            .suppression_eos = 0,
            .suppression_sos = 0,
            .min_tr2 = 30
    };
    EXPECT_CALL(mock_nfa_update, nfa_sys_sendmsg(testing::_)).Times(0);
    tNFA_STATUS result = NFA_UpdateRFCommParams(&rf_params);
    EXPECT_EQ(result, NFA_STATUS_FAILED);
}
