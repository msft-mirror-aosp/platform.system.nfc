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
#include "nfa_dm_discover.cc"

using ::testing::_;
using ::testing::StrictMock;
using ::testing::Return;

#define NFC_PROTOCOL_INVALID 0xFF
#ifndef NFC_INTERFACE_NFC_DEP
#define NFC_INTERFACE_NFC_DEP 0x02
#endif

class MockRWSleepWakeupHandler {
public:
    MOCK_METHOD(void, HandleSleepWakeupResponse, (tNFC_STATUS status), ());
};

class MockDiscSMExecuteHandler {
public:
    MOCK_METHOD(void, Execute, (uint8_t event, tNFA_DM_RF_DISC_DATA* p_data), ());
};

class MockExclusiveCallbackHandler {
public:
    MOCK_METHOD(void, Callback, (uint8_t event, tNFA_CONN_EVT_DATA* evt_data));
};

class MockConnectionCallbackHandler {
public:
    MOCK_METHOD(void, Callback, (uint8_t event, tNFA_CONN_EVT_DATA* evt_data));
};

class MockNfc {
public:
    MOCK_METHOD(tNFC_STATUS, Deactivate, (tNFC_DEACT_TYPE deactivate_type), ());
};

class MockNfaDm {
public:
    MOCK_METHOD(void, DiscNewState, (uint8_t new_state), ());
};

class MockNfaSys {
public:
    MOCK_METHOD(void, nfa_sys_start_timer, (TIMER_LIST_ENT*, uint16_t, uint16_t), ());
    MOCK_METHOD(void, nfa_dm_disc_report_kovio_presence_check, (tNFA_STATUS), ());
};

MockNfaSys* g_mock_nfa_sys = nullptr;

class NfaDmMock {
public:
    MOCK_METHOD(void, nfa_dm_disc_report_kovio_presence_check,(tNFC_STATUS status), ());
    MOCK_METHOD(void, nfa_sys_start_timer,(TIMER_LIST_ENT*, uint16_t event, uint16_t timeout), ());
    MOCK_METHOD(void, nfa_dm_disc_notify_deactivation,(uint8_t event, tNFC_DISCOVER* p_data), ());
};

class NfaDMDisc {
public:
    MOCK_METHOD(tNFA_STATUS, nfa_dm_send_deactivate_cmd, (tNFA_DM_RF_DISC_SM_EVENT event), ());
    MOCK_METHOD(void, nfa_dm_disc_notify_deactivation,(tNFA_DM_RF_DISC_SM_EVENT event,
                                                       tNFC_DISCOVER *p_data),());
    MOCK_METHOD(void, nfa_dm_disc_new_state,(tNFA_DM_RF_DISC_STATE new_state),());
    MOCK_METHOD(void, NFC_DiscoverySelect,(int rf_disc_id, int protocol, int interface),());
    MOCK_METHOD(void, nfa_dm_disc_end_sleep_wakeup,(tNFC_STATUS status),());
    MOCK_METHOD(void, nfa_wlc_event_notify, (tNFA_WLC_EVT event, tNFA_WLC_EVT_DATA* p_data));
};

StrictMock<MockNfc> mock_nfc;
StrictMock<MockNfaDm> mock_nfa_dm;
MockExclusiveCallbackHandler* g_mock_excl_handler = nullptr;
MockConnectionCallbackHandler* g_mock_conn_handler = nullptr;

void ForwardExclusiveCallback(uint8_t event, tNFA_CONN_EVT_DATA* evt_data) {
    if (g_mock_excl_handler) {
        g_mock_excl_handler->Callback(event, evt_data);
    }
}

void ForwardConnectionCallback(uint8_t event, tNFA_CONN_EVT_DATA* evt_data) {
    if (g_mock_conn_handler) {
        g_mock_conn_handler->Callback(event, evt_data);
    }
}

class NfaDmDiscConnEventNotifyTest : public ::testing::Test {
protected:
    StrictMock<MockExclusiveCallbackHandler> mock_excl_handler;
    StrictMock<MockConnectionCallbackHandler> mock_conn_handler;

    void SetUp() override {
        g_mock_excl_handler = &mock_excl_handler;
        g_mock_conn_handler = &mock_conn_handler;
        nfa_dm_cb.p_excl_conn_cback = ForwardExclusiveCallback;
        nfa_dm_cb.p_conn_cback = ForwardConnectionCallback;
        nfa_dm_cb.disc_cb.disc_flags = 0;
        nfa_dm_cb.flags = 0;
    }

    void TearDown() override {
        g_mock_excl_handler = nullptr;
        g_mock_conn_handler = nullptr;
    }
};

TEST_F(NfaDmDiscConnEventNotifyTest, ExclusiveRfModeCallbackTriggered) {
    nfa_dm_cb.disc_cb.disc_flags = NFA_DM_DISC_FLAGS_NOTIFY;
    nfa_dm_cb.flags = NFA_DM_FLAGS_EXCL_RF_ACTIVE;
    uint8_t event = 0x01;
    tNFA_STATUS status = NFA_STATUS_OK;
    EXPECT_CALL(mock_excl_handler, Callback(event, _)).Times(1);
    nfa_dm_disc_conn_event_notify(event, status);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_NOTIFY, 0);
}

TEST_F(NfaDmDiscConnEventNotifyTest, NormalCallbackTriggered) {
    nfa_dm_cb.disc_cb.disc_flags = NFA_DM_DISC_FLAGS_NOTIFY;
    uint8_t event = 0x02;
    tNFA_STATUS status = NFA_STATUS_FAILED;
    EXPECT_CALL(mock_conn_handler, Callback(event, _)).Times(1);
    nfa_dm_disc_conn_event_notify(event, status);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_NOTIFY, 0);
}

TEST_F(NfaDmDiscConnEventNotifyTest, CallbackNotTriggeredWhenNotifyFlagNotSet) {
    nfa_dm_cb.disc_cb.disc_flags = 0;
    uint8_t event = 0x03;
    tNFA_STATUS status = NFA_STATUS_OK;
    EXPECT_CALL(mock_excl_handler, Callback(_, _)).Times(0);
    EXPECT_CALL(mock_conn_handler, Callback(_, _)).Times(0);
    nfa_dm_disc_conn_event_notify(event, status);
}

class NfaDmDiscDeactNtfTimeoutCbackTest : public ::testing::Test {
protected:
    void SetUp() override {
        nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_IDLE;
    }
    void TearDown() override {
    }
    MOCK_METHOD(void, mock_disc_sm_execute, (uint8_t event, tNFA_DM_RF_DISC_DATA* p_data), ());
    MOCK_METHOD(void, mock_disc_force_to_idle, (), ());
};

TEST_F(NfaDmDiscDeactNtfTimeoutCbackTest, TestDiscStateListenActive) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LISTEN_ACTIVE;
    tNFA_DM_RF_DISC_DATA p_data;
    p_data.nfc_discover.deactivate.status = NFC_STATUS_OK;
    p_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_IDLE;
    p_data.nfc_discover.deactivate.is_ntf = true;
    p_data.nfc_discover.deactivate.reason = NFC_DEACTIVATE_REASON_DH_REQ;
    EXPECT_CALL(*this, mock_disc_sm_execute(NFA_DM_RF_DEACTIVATE_NTF, &p_data)).Times(0);
    nfa_dm_disc_deact_ntf_timeout_cback(nullptr);
}

TEST_F(NfaDmDiscDeactNtfTimeoutCbackTest, TestDiscStateNotListenActive) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_IDLE;
    EXPECT_CALL(*this, mock_disc_force_to_idle()).Times(0);
    nfa_dm_disc_deact_ntf_timeout_cback(nullptr);
}

TEST_F(NfaDmDiscDeactNtfTimeoutCbackTest, TestDiscStateListenActiveWithNullCallback) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LISTEN_ACTIVE;
    nfa_dm_cb.p_excl_conn_cback = nullptr;
    nfa_dm_disc_deact_ntf_timeout_cback(nullptr);
}

TEST_F(NfaDmDiscDeactNtfTimeoutCbackTest, TestDiscStateListenActiveWithCallbackSet) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LISTEN_ACTIVE;
    nfa_dm_cb.p_excl_conn_cback = [](uint8_t event, tNFA_CONN_EVT_DATA* evt_data) {
        EXPECT_EQ(event, NFA_DM_RF_DEACTIVATE_NTF);
        EXPECT_EQ(evt_data->status, NFC_STATUS_OK);
    };
    tNFA_DM_RF_DISC_DATA p_data;
    p_data.nfc_discover.deactivate.status = NFC_STATUS_OK;
    p_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_IDLE;
    p_data.nfc_discover.deactivate.is_ntf = true;
    p_data.nfc_discover.deactivate.reason = NFC_DEACTIVATE_REASON_DH_REQ;
    EXPECT_CALL(*this, mock_disc_sm_execute(NFA_DM_RF_DEACTIVATE_NTF, &p_data)).Times(0);
    nfa_dm_disc_deact_ntf_timeout_cback(nullptr);
}

TEST_F(NfaDmDiscDeactNtfTimeoutCbackTest, TestInvalidDataNullPointer) {
    nfa_dm_disc_deact_ntf_timeout_cback(nullptr);
}

TEST_F(NfaDmDiscDeactNtfTimeoutCbackTest, TestDiscStateListenActiveAndResetCallback) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LISTEN_ACTIVE;
    nfa_dm_cb.p_excl_conn_cback = nullptr;
    EXPECT_CALL(*this, mock_disc_sm_execute(NFA_DM_RF_DEACTIVATE_NTF, testing::_)).Times(0);
    nfa_dm_disc_deact_ntf_timeout_cback(nullptr);
}

class NfaDmDiscEndSleepWakeupTest : public ::testing::Test {
protected:
    StrictMock<MockRWSleepWakeupHandler> mock_rw_handler;
    StrictMock<MockDiscSMExecuteHandler> mock_disc_sm_execute;

    void SetUp() override {
        nfa_dm_cb.disc_cb.activated_protocol = NFC_PROTOCOL_INVALID;
        nfa_dm_cb.disc_cb.kovio_tle.in_use = false;
        nfa_dm_cb.disc_cb.disc_flags = 0;
        nfa_dm_cb.disc_cb.deact_pending = false;
        nfa_dm_cb.disc_cb.deact_notify_pending = false;
        nfa_dm_cb.disc_cb.pending_deact_type = NFC_DEACTIVATE_TYPE_IDLE;
    }

    void TearDown() override {
    }
};

TEST_F(NfaDmDiscEndSleepWakeupTest, TestKovioPresenceCheckActive) {
    nfa_dm_cb.disc_cb.activated_protocol = NFC_PROTOCOL_KOVIO;
    nfa_dm_cb.disc_cb.kovio_tle.in_use = true;
    EXPECT_CALL(mock_rw_handler, HandleSleepWakeupResponse(_)).Times(0);
    nfa_dm_disc_end_sleep_wakeup(NFC_STATUS_OK);
}

TEST_F(NfaDmDiscEndSleepWakeupTest, TestSleepWakeupCheckingFlagSet) {
    nfa_dm_cb.disc_cb.disc_flags = NFA_DM_DISC_FLAGS_CHECKING;
    EXPECT_CALL(mock_rw_handler, HandleSleepWakeupResponse(NFC_STATUS_OK)).Times(0);
    nfa_dm_disc_end_sleep_wakeup(NFC_STATUS_OK);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_CHECKING, 0);
}

TEST_F(NfaDmDiscEndSleepWakeupTest, TestPendingDeactivation) {
    nfa_dm_cb.disc_cb.disc_flags = NFA_DM_DISC_FLAGS_CHECKING;
    nfa_dm_cb.disc_cb.deact_pending = true;
    nfa_dm_cb.disc_cb.pending_deact_type = NFC_DEACTIVATE_TYPE_IDLE;
    EXPECT_CALL(mock_rw_handler, HandleSleepWakeupResponse(NFC_STATUS_OK)).Times(0);
    EXPECT_CALL(mock_disc_sm_execute, Execute(NFA_DM_RF_DEACTIVATE_CMD, _)).Times(0);
    nfa_dm_disc_end_sleep_wakeup(NFC_STATUS_OK);
    EXPECT_FALSE(nfa_dm_cb.disc_cb.deact_pending);
    EXPECT_TRUE(nfa_dm_cb.disc_cb.deact_notify_pending);
}

TEST_F(NfaDmDiscEndSleepWakeupTest, TestNormalCaseWithNoPendingDeactivation) {
    nfa_dm_cb.disc_cb.disc_flags = NFA_DM_DISC_FLAGS_CHECKING;
    nfa_dm_cb.disc_cb.deact_pending = false;
    EXPECT_CALL(mock_rw_handler, HandleSleepWakeupResponse(NFC_STATUS_OK)).Times(0);
    nfa_dm_disc_end_sleep_wakeup(NFC_STATUS_OK);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_CHECKING, 0);
}

TEST_F(NfaDmDiscEndSleepWakeupTest, TestNoCheckingFlag) {
    nfa_dm_cb.disc_cb.disc_flags = 0;
    EXPECT_CALL(mock_rw_handler, HandleSleepWakeupResponse(_)).Times(0);
    nfa_dm_disc_end_sleep_wakeup(NFC_STATUS_OK);
}

TEST_F(NfaDmDiscEndSleepWakeupTest, TestInvalidStatus) {
    nfa_dm_cb.disc_cb.disc_flags = NFA_DM_DISC_FLAGS_CHECKING;
    EXPECT_CALL(mock_rw_handler, HandleSleepWakeupResponse(NFC_STATUS_FAILED)).Times(0);
    nfa_dm_disc_end_sleep_wakeup(NFC_STATUS_FAILED);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_CHECKING, 0);
}

class NfaDmDiscEvent2StrTest : public ::testing::Test {
protected:
};

TEST_F(NfaDmDiscEvent2StrTest, KnownEvents) {
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_RF_DISCOVER_CMD), "DISCOVER_CMD");
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_RF_DISCOVER_RSP), "DISCOVER_RSP");
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_RF_DISCOVER_NTF), "DISCOVER_NTF");
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_RF_DISCOVER_SELECT_CMD), "SELECT_CMD");
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_RF_DISCOVER_SELECT_RSP), "SELECT_RSP");
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_RF_INTF_ACTIVATED_NTF), "ACTIVATED_NTF");
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_RF_DEACTIVATE_CMD), "DEACTIVATE_CMD");
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_RF_DEACTIVATE_RSP), "DEACTIVATE_RSP");
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_RF_DEACTIVATE_NTF), "DEACTIVATE_NTF");
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_LP_LISTEN_CMD), "NFA_DM_LP_LISTEN_CMD");
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_CORE_INTF_ERROR_NTF), "INTF_ERROR_NTF");
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_WPT_START_CMD), "WPT_START_CMD");
    EXPECT_EQ(nfa_dm_disc_event_2_str(NFA_DM_WPT_START_RSP), "WPT_START_RSP");
}

TEST_F(NfaDmDiscEvent2StrTest, UnknownEvent){
    EXPECT_EQ(nfa_dm_disc_event_2_str(0xFF), "Unknown");  // 0xFF is UNKNOWN EVENT
}

class NfaDmDiscForceToIdleTest : public ::testing::Test {
protected:
    void SetUp() override {
        nfa_dm_cb.disc_cb.disc_flags = 0;
    }
    void TearDown() override {
    }
};

TEST_F(NfaDmDiscForceToIdleTest, ForceToIdleWhenW4NtfSet) {
    nfa_dm_cb.disc_cb.disc_flags = NFA_DM_DISC_FLAGS_W4_NTF;
    EXPECT_CALL(mock_nfc, Deactivate(NFC_DEACTIVATE_TYPE_IDLE)).WillOnce(Return(NFC_STATUS_OK));
    EXPECT_CALL(mock_nfa_dm, DiscNewState(NFA_DM_RFST_IDLE)).Times(1);
    tNFC_STATUS status = nfa_dm_disc_force_to_idle();
    EXPECT_EQ(status, NFC_STATUS_OK);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags, NFA_DM_DISC_FLAGS_W4_RSP);
}

TEST_F(NfaDmDiscForceToIdleTest, ForceToIdleWhenW4NtfNotSet) {
    nfa_dm_cb.disc_cb.disc_flags = 0;
    EXPECT_CALL(mock_nfc, Deactivate(_)).Times(0);
    EXPECT_CALL(mock_nfa_dm, DiscNewState(_)).Times(0);
    tNFC_STATUS status = nfa_dm_disc_force_to_idle();
    EXPECT_EQ(status, NFC_STATUS_SEMANTIC_ERROR);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags, 0);
}

TEST_F(NfaDmDiscForceToIdleTest, ForceToIdleWithMultipleFlagsSet) {
    nfa_dm_cb.disc_cb.disc_flags = NFA_DM_DISC_FLAGS_W4_NTF | 0x10;
    EXPECT_CALL(mock_nfc, Deactivate(NFC_DEACTIVATE_TYPE_IDLE)).WillOnce(Return(NFC_STATUS_OK));
    EXPECT_CALL(mock_nfa_dm, DiscNewState(NFA_DM_RFST_IDLE)).Times(1);
    tNFC_STATUS status = nfa_dm_disc_force_to_idle();
    EXPECT_EQ(status, NFC_STATUS_OK);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags, NFA_DM_DISC_FLAGS_W4_RSP | 0x10);
}

TEST_F(NfaDmDiscForceToIdleTest, AlreadyInIdleState) {
    nfa_dm_cb.disc_cb.disc_flags = NFA_DM_DISC_FLAGS_W4_NTF;
    EXPECT_CALL(mock_nfa_dm, DiscNewState(NFA_DM_RFST_IDLE)).Times(1);
    EXPECT_CALL(mock_nfc, Deactivate(NFC_DEACTIVATE_TYPE_IDLE)).WillOnce(Return(NFC_STATUS_OK));
    tNFC_STATUS status = nfa_dm_disc_force_to_idle();
    EXPECT_EQ(status, NFC_STATUS_OK);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags, NFA_DM_DISC_FLAGS_W4_RSP);
}

TEST_F(NfaDmDiscForceToIdleTest, IrrelevantFlagsPresent) {
    nfa_dm_cb.disc_cb.disc_flags = NFA_DM_DISC_FLAGS_W4_NTF | 0x20;
    EXPECT_CALL(mock_nfc, Deactivate(NFC_DEACTIVATE_TYPE_IDLE)).WillOnce(Return(NFC_STATUS_OK));
    EXPECT_CALL(mock_nfa_dm, DiscNewState(NFA_DM_RFST_IDLE)).Times(1);
    tNFC_STATUS status = nfa_dm_disc_force_to_idle();
    EXPECT_EQ(status, NFC_STATUS_OK);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags, NFA_DM_DISC_FLAGS_W4_RSP | 0x20);
}

TEST_F(NfaDmDiscForceToIdleTest, NoEffectWhenFlagsNotSet) {
    nfa_dm_cb.disc_cb.disc_flags = 0x20;
    EXPECT_CALL(mock_nfc, Deactivate(_)).Times(0);
    EXPECT_CALL(mock_nfa_dm, DiscNewState(_)).Times(0);
    tNFC_STATUS status = nfa_dm_disc_force_to_idle();
    EXPECT_EQ(status, NFC_STATUS_SEMANTIC_ERROR);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags, 0x20);
}

class NfaDmDiscGetDiscMaskTest : public testing::Test {
protected:
    void SetUp() override {
    }

    void TearDown() override {
    }
};

TEST_F(NfaDmDiscGetDiscMaskTest, ReturnsLegacyPollMaskForUnknownTech) {
    tNFA_DM_DISC_TECH_PROTO_MASK disc_mask = nfa_dm_disc_get_disc_mask(0x00, NFC_PROTOCOL_UNKNOWN);
    EXPECT_EQ(disc_mask, NFA_DM_DISC_MASK_P_LEGACY);
}

TEST_F(NfaDmDiscGetDiscMaskTest, ReturnsLegacyListenMaskForHighTechBit) {
    tNFA_DM_DISC_TECH_PROTO_MASK disc_mask = nfa_dm_disc_get_disc_mask(0x80, NFC_PROTOCOL_UNKNOWN);
    EXPECT_EQ(disc_mask, NFA_DM_DISC_MASK_L_LEGACY);
}

TEST_F(NfaDmDiscGetDiscMaskTest, HandlesPollATechWithVariousProtocols) {
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_POLL_A, NFC_PROTOCOL_T1T),
              NFA_DM_DISC_MASK_PA_T1T);
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_POLL_A, NFC_PROTOCOL_T2T),
              NFA_DM_DISC_MASK_PA_T2T);
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_POLL_A, NFC_PROTOCOL_ISO_DEP),
              NFA_DM_DISC_MASK_PA_ISO_DEP);
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_POLL_A, NFC_PROTOCOL_NFC_DEP),
              NFA_DM_DISC_MASK_PA_NFC_DEP);
}

TEST_F(NfaDmDiscGetDiscMaskTest, HandlesPollBTechWithVariousProtocols) {
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_POLL_B, NFC_PROTOCOL_ISO_DEP),
              NFA_DM_DISC_MASK_PB_ISO_DEP);
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_POLL_B, NCI_PROTOCOL_UNKNOWN),
              NFA_DM_DISC_MASK_PB_CI);
}

TEST_F(NfaDmDiscGetDiscMaskTest, HandlesPollFTechWithVariousProtocols) {
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_POLL_F, NFC_PROTOCOL_T3T),
              NFA_DM_DISC_MASK_PF_T3T);
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_POLL_F, NFC_PROTOCOL_NFC_DEP),
              NFA_DM_DISC_MASK_PF_NFC_DEP);
}

TEST_F(NfaDmDiscGetDiscMaskTest, HandlesPollVTech) {
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_POLL_V, NFC_PROTOCOL_UNKNOWN),
              NFA_DM_DISC_MASK_P_T5T);
}

TEST_F(NfaDmDiscGetDiscMaskTest, HandlesPollBPrimeTech) {
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_POLL_B_PRIME, NFC_PROTOCOL_UNKNOWN),
              NFA_DM_DISC_MASK_P_B_PRIME);
}

TEST_F(NfaDmDiscGetDiscMaskTest, HandlesPollKovioTech) {
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_POLL_KOVIO, NFC_PROTOCOL_UNKNOWN),
              NFA_DM_DISC_MASK_P_KOVIO);
}

TEST_F(NfaDmDiscGetDiscMaskTest, HandlesListenATechWithVariousProtocols) {
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_LISTEN_A, NFC_PROTOCOL_T1T),
              NFA_DM_DISC_MASK_LA_T1T);
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_LISTEN_A, NFC_PROTOCOL_T2T),
              NFA_DM_DISC_MASK_LA_T2T);
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_LISTEN_A, NFC_PROTOCOL_ISO_DEP),
              NFA_DM_DISC_MASK_LA_ISO_DEP);
}

TEST_F(NfaDmDiscGetDiscMaskTest, HandlesListenBTechWithISOProtocol) {
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_LISTEN_B, NFC_PROTOCOL_ISO_DEP),
              NFA_DM_DISC_MASK_LB_ISO_DEP);
}

TEST_F(NfaDmDiscGetDiscMaskTest, HandlesListenFTechWithT3TProtocol) {
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_LISTEN_F, NFC_PROTOCOL_T3T),
              NFA_DM_DISC_MASK_LF_T3T);
}

TEST_F(NfaDmDiscGetDiscMaskTest, HandlesListenISO15693Tech) {
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_LISTEN_ISO15693, NFC_PROTOCOL_UNKNOWN),
              NFA_DM_DISC_MASK_L_ISO15693);
}

TEST_F(NfaDmDiscGetDiscMaskTest, HandlesListenBPrimeTech) {
    EXPECT_EQ(nfa_dm_disc_get_disc_mask(NFC_DISCOVERY_TYPE_LISTEN_B_PRIME, NFC_PROTOCOL_UNKNOWN),
              NFA_DM_DISC_MASK_L_B_PRIME);
}

tNFC_DISCOVER CreateDiscoverData(const uint8_t* uid, size_t uid_len) {
    tNFC_DISCOVER data{};
    if (uid && uid_len > 0) {
        data.activate.rf_tech_param.param.pk.uid_len = uid_len;
        memcpy(data.activate.rf_tech_param.param.pk.uid, uid, uid_len);
    }
    return data;
}

void InitializeKovioState(bool in_use, const uint8_t* uid, size_t uid_len) {
    nfa_dm_cb.disc_cb.kovio_tle.in_use = in_use;
    if (uid && uid_len > 0) {
        nfa_dm_cb.activated_nfcid_len = uid_len;
        memcpy(nfa_dm_cb.activated_nfcid, uid, uid_len);
    }
}
void MockDiscoverCallback(uint8_t, tNFC_DISCOVER*) {
}

class NfaDmDiscHandleKovioActivationTest : public testing::Test {
protected:
    MockNfaSys mock_nfa_sys;
    void SetUp() override {
        g_mock_nfa_sys = &mock_nfa_sys;
    }
    void TearDown() override {
        g_mock_nfa_sys = nullptr;
    }
};

TEST_F(NfaDmDiscHandleKovioActivationTest, FirstActivationStartsTimerAndNotifiesUpperLayer) {
    tNFC_DISCOVER discover_data = {};
    tNFA_DISCOVER_CBACK* mock_callback = MockDiscoverCallback;
    EXPECT_CALL(mock_nfa_sys,
                nfa_sys_start_timer(_, _, NFA_DM_DISC_TIMEOUT_KOVIO_PRESENCE_CHECK)).Times(0);
    bool result = nfa_dm_disc_handle_kovio_activation(&discover_data, mock_callback);
    EXPECT_FALSE(result);
}

TEST_F(NfaDmDiscHandleKovioActivationTest, NewTagNotifiesUpperLayerAndRestartsTimer) {
    uint8_t existing_uid[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t new_uid[] = {0x05, 0x06, 0x07, 0x08};
    InitializeKovioState(
            true, existing_uid, sizeof(existing_uid));
    tNFC_DISCOVER discover_data = CreateDiscoverData(new_uid, sizeof(new_uid));
    EXPECT_CALL(mock_nfa_sys, nfa_dm_disc_report_kovio_presence_check(NFA_STATUS_FAILED)).Times(0);
    EXPECT_CALL(mock_nfa_sys,
                nfa_sys_start_timer(_, _, NFA_DM_DISC_TIMEOUT_KOVIO_PRESENCE_CHECK)).Times(0);
    bool result = nfa_dm_disc_handle_kovio_activation(&discover_data, nullptr);
    EXPECT_FALSE(result);
}

TEST_F(NfaDmDiscHandleKovioActivationTest, SameTagRestartsTimerAndDoesNotNotifyUpperLayer) {
    uint8_t uid[] = {0x01, 0x02, 0x03, 0x04};
    InitializeKovioState(true, uid, sizeof(uid));
    tNFC_DISCOVER discover_data = CreateDiscoverData(uid, sizeof(uid));
    EXPECT_CALL(mock_nfa_sys, nfa_dm_disc_report_kovio_presence_check(NFC_STATUS_OK)).Times(0);
    EXPECT_CALL(mock_nfa_sys,
                nfa_sys_start_timer(_, _, NFA_DM_DISC_TIMEOUT_KOVIO_PRESENCE_CHECK)).Times(0);
    bool result = nfa_dm_disc_handle_kovio_activation(&discover_data, nullptr);
    EXPECT_TRUE(result);
}

TEST_F(NfaDmDiscHandleKovioActivationTest, NoTimerOnInactiveStateStartsTimer) {
    uint8_t uid[] = {0x01, 0x02, 0x03, 0x04};
    InitializeKovioState(false, nullptr, 0);
    tNFC_DISCOVER discover_data = CreateDiscoverData(uid, sizeof(uid));
    EXPECT_CALL(mock_nfa_sys,
                nfa_sys_start_timer(_, _, NFA_DM_DISC_TIMEOUT_KOVIO_PRESENCE_CHECK)).Times(0);
    bool result = nfa_dm_disc_handle_kovio_activation(&discover_data, nullptr);
    EXPECT_FALSE(result);
}

TEST_F(NfaDmDiscHandleKovioActivationTest, DifferentUIDLengthsAreTreatedAsNewTag) {
    uint8_t existing_uid[] = {0x01, 0x02, 0x03};
    uint8_t new_uid[] = {0x01, 0x02, 0x03, 0x04};
    InitializeKovioState(
            true, existing_uid, sizeof(existing_uid));
    tNFC_DISCOVER discover_data = CreateDiscoverData(new_uid, sizeof(new_uid));
    EXPECT_CALL(mock_nfa_sys, nfa_dm_disc_report_kovio_presence_check(NFC_STATUS_FAILED)).Times(0);
    EXPECT_CALL(mock_nfa_sys,
                nfa_sys_start_timer(_, _, NFA_DM_DISC_TIMEOUT_KOVIO_PRESENCE_CHECK)).Times(0);
    bool result = nfa_dm_disc_handle_kovio_activation(&discover_data, nullptr);
    EXPECT_FALSE(result);
}
NfaDmMock* g_nfa_dm_mock = nullptr;

class NfaDmDiscKovioTimeoutTest : public testing::Test {
protected:
    NfaDmMock mock;
    void SetUp() override {
        g_nfa_dm_mock = new NfaDmMock();
        memset(&nfa_dm_cb, 0, sizeof(nfa_dm_cb));
    }
    void TearDown() override {

    }
};

TEST_F(NfaDmDiscKovioTimeoutTest, TimerRestartsInActiveState) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_POLL_ACTIVE;
    EXPECT_CALL(mock, nfa_dm_disc_report_kovio_presence_check(NFC_STATUS_FAILED)).Times(0);
    EXPECT_CALL(mock, nfa_sys_start_timer(
            &nfa_dm_cb.disc_cb.kovio_tle, 0,NFA_DM_DISC_TIMEOUT_KOVIO_PRESENCE_CHECK)).Times(0);
    nfa_dm_disc_kovio_timeout_cback(&nfa_dm_cb.disc_cb.kovio_tle);
}

TEST_F(NfaDmDiscKovioTimeoutTest, DeactivationNotificationInInactiveState) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_IDLE;
    EXPECT_CALL(mock, nfa_dm_disc_report_kovio_presence_check(NFC_STATUS_FAILED)).Times(0);
    tNFC_DISCOVER expected_data;
    expected_data.deactivate.status = NFC_STATUS_OK;
    expected_data.deactivate.type = NFC_DEACTIVATE_TYPE_DISCOVERY;
    expected_data.deactivate.is_ntf = true;
    expected_data.deactivate.reason = NFC_DEACTIVATE_REASON_DH_REQ;
    EXPECT_CALL(mock, nfa_dm_disc_notify_deactivation(
            NFA_DM_RF_DEACTIVATE_NTF,testing::Truly([&expected_data](const tNFC_DISCOVER* actual) {
                return actual->deactivate.status == expected_data.deactivate.status &&
                actual->deactivate.type == expected_data.deactivate.type &&
                actual->deactivate.is_ntf == expected_data.deactivate.is_ntf &&
                actual->deactivate.reason == expected_data.deactivate.reason;
            }))).Times(0);
    nfa_dm_disc_kovio_timeout_cback(&nfa_dm_cb.disc_cb.kovio_tle);
}

TEST_F(NfaDmDiscKovioTimeoutTest, NoOperationIfTimerInactive) {
    nfa_dm_cb.disc_cb.kovio_tle.in_use = false;
    EXPECT_CALL(mock, nfa_dm_disc_report_kovio_presence_check).Times(0);
    EXPECT_CALL(mock, nfa_sys_start_timer).Times(0);
    EXPECT_CALL(mock, nfa_dm_disc_notify_deactivation).Times(0);
    nfa_dm_disc_kovio_timeout_cback(&nfa_dm_cb.disc_cb.kovio_tle);
}


class NfaDmNoti {
public:
    MOCK_METHOD(bool, nfa_dm_disc_handle_kovio_activation,
            (tNFC_DISCOVER* p_data, tNFA_DISCOVER_CBACK* p_cback), ());
    MOCK_METHOD(void, nfa_dm_cb_excl_disc_callback,
            (tNFA_DM_RF_DISC_EVT event, tNFC_DISCOVER* p_data), ());
    MOCK_METHOD(void, nfa_sys_start_timer,(TIMER_LIST_ENT*, uint16_t event, uint16_t timeout), ());
    MOCK_METHOD(void, nfa_dm_entry_disc_callback,(
            tNFA_DM_RF_DISC_EVT event, tNFC_DISCOVER* p_data), ());
    MOCK_METHOD(void, nfa_dm_conn_cback_event_notify, (
            tNFA_EE_EVT event,tNFA_CONN_EVT_DATA* p_data), ());
};

NfaDmNoti* g_nfa_dm_noti = nullptr;

class NfaDmDiscNotifyActivationTest : public testing::Test {
protected:
    tNFC_DISCOVER test_data;

    void SetUp() override {
        g_nfa_dm_noti = new NfaDmNoti();
        memset(&test_data, 0, sizeof(test_data));
    }
    void TearDown() override {
        testing::Mock::AllowLeak(reinterpret_cast<const void*>(&g_nfa_dm_noti));
    }
};

TEST_F(NfaDmDiscNotifyActivationTest, ExclusiveDiscoveryActivation) {
    nfa_dm_cb.disc_cb.excl_disc_entry.in_use = true;
    nfa_dm_cb.disc_cb.excl_disc_entry.p_disc_cback =[](tNFA_DM_RF_DISC_EVT , tNFC_DISCOVER*) {};
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_cb_excl_disc_callback(_, _)).Times(1);
    EXPECT_EQ(nfa_dm_disc_notify_activation(&test_data), NFA_STATUS_OK);
}

TEST_F(NfaDmDiscNotifyActivationTest, KovioProtocolActivation) {
    test_data.activate.protocol = NFC_PROTOCOL_KOVIO;
    nfa_dm_cb.disc_cb.excl_disc_entry.in_use = true;
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_disc_handle_kovio_activation(
            &test_data, _)).WillOnce(Return(true));
    EXPECT_EQ(nfa_dm_disc_notify_activation(&test_data), NFA_STATUS_OK);
}

TEST_F(NfaDmDiscNotifyActivationTest, NfceeDirectRfInterfaceActivation) {
    test_data.activate.intf_param.type = NFC_INTERFACE_EE_DIRECT_RF;
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_entry_disc_callback(_, _)).Times(1);
    EXPECT_EQ(nfa_dm_disc_notify_activation(&test_data), NFA_STATUS_OK);
}

TEST_F(NfaDmDiscNotifyActivationTest, ValidTechAndProtocolMatch) {
    test_data.activate.rf_tech_param.mode = NFC_DISCOVERY_TYPE_LISTEN_A;
    test_data.activate.protocol = NFC_PROTOCOL_T3T;
    nfa_dm_cb.disc_cb.listen_RT[NFA_DM_DISC_LRT_NFC_A] = NFA_DM_DISC_HOST_ID_DH;
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_entry_disc_callback(_, _)).Times(1);
    EXPECT_EQ(nfa_dm_disc_notify_activation(&test_data), NFA_STATUS_OK);
}

//nfa_dm_disc_notify_deactivation

TEST_F(NfaDmDiscNotifyActivationTest, SleepModeCheck) {
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_CHECKING;
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_cb_excl_disc_callback(_, _)).Times(0);
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_entry_disc_callback(_, _)).Times(0);
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_conn_cback_event_notify(_, _)).Times(0);
    nfa_dm_disc_notify_deactivation(NFA_DM_RF_DEACTIVATE_RSP, &test_data);
}

TEST_F(NfaDmDiscNotifyActivationTest, DeactivationInListenSleepState) {
    nfa_dm_cb.disc_cb.disc_flags &= ~NFA_DM_DISC_FLAGS_CHECKING;
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LISTEN_SLEEP;
    nfa_dm_cb.disc_cb.excl_disc_entry.in_use = true;
    nfa_dm_cb.disc_cb.excl_disc_entry.p_disc_cback = [](tNFA_DM_RF_DISC_EVT, tNFC_DISCOVER*) {};
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_cb_excl_disc_callback(_, _)).Times(1);
    nfa_dm_disc_notify_deactivation(NFA_DM_RF_DEACTIVATE_RSP, &test_data);
}

TEST_F(NfaDmDiscNotifyActivationTest, NoActivatedModule) {
    nfa_dm_cb.disc_cb.activated_handle = NFA_HANDLE_INVALID;
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_conn_cback_event_notify(NFA_DEACTIVATED_EVT, _)).Times(1);
    nfa_dm_disc_notify_deactivation(NFA_DM_RF_DEACTIVATE_RSP, &test_data);
}

TEST_F(NfaDmDiscNotifyActivationTest, ReactivationFailure) {
    nfa_dm_cb.disc_cb.deact_notify_pending = true;
    nfa_dm_cb.disc_cb.activated_handle = 0;
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_entry_disc_callback(
            NFA_DM_RF_DISC_DEACTIVATED_EVT, _)).Times(1);
    nfa_dm_disc_notify_deactivation(NFA_DM_RF_DEACTIVATE_RSP, &test_data);
}

TEST_F(NfaDmDiscNotifyActivationTest, KovioProtocolHandling) {
    nfa_dm_cb.disc_cb.activated_protocol = NFC_PROTOCOL_KOVIO;
    nfa_dm_cb.disc_cb.kovio_tle.in_use = true;
    EXPECT_CALL(*g_nfa_dm_noti,
                nfa_sys_start_timer(_, _, NFA_DM_DISC_TIMEOUT_KOVIO_PRESENCE_CHECK)).Times(1);
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_cb_excl_disc_callback(_, _)).Times(0);
    nfa_dm_disc_notify_deactivation(NFA_DM_RF_DEACTIVATE_RSP, &test_data);
}

TEST_F(NfaDmDiscNotifyActivationTest, ActivatedModuleHandling) {
    nfa_dm_cb.disc_cb.activated_handle = 0;
    nfa_dm_cb.disc_cb.entry[0].in_use = true;
    nfa_dm_cb.disc_cb.entry[0].p_disc_cback = [](tNFA_DM_RF_DISC_EVT, tNFC_DISCOVER*) {};
    EXPECT_CALL(*g_nfa_dm_noti,
                nfa_dm_entry_disc_callback(NFA_DM_RF_DISC_DEACTIVATED_EVT, _)).Times(1);
    nfa_dm_disc_notify_deactivation(NFA_DM_RF_DEACTIVATE_RSP, &test_data);
}

TEST_F(NfaDmDiscNotifyActivationTest, ConcurrentDeactivationHandling) {
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_CHECKING;
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LISTEN_SLEEP;
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_cb_excl_disc_callback(_, _)).Times(0);
    EXPECT_CALL(*g_nfa_dm_noti, nfa_dm_entry_disc_callback(_, _)).Times(0);
    nfa_dm_disc_notify_deactivation(NFA_DM_RF_DEACTIVATE_RSP, &test_data);
    nfa_dm_disc_notify_deactivation(NFA_DM_RF_DEACTIVATE_RSP, &test_data);
    EXPECT_TRUE(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_CHECKING);
}

class NfaDmDiscSleepWakeupTest : public testing::Test {
protected:
    void SetUp() override {
        memset(&nfa_dm_cb, 0, sizeof(nfa_dm_cb));
    }
    void TearDown() override {
        memset(&nfa_dm_cb, 0, sizeof(nfa_dm_cb));
    }
    MOCK_METHOD(tNFC_STATUS, nfa_dm_send_deactivate_cmd, (tNFC_DEACT_TYPE deactivate_type), ());
};

TEST_F(NfaDmDiscSleepWakeupTest, OperationFailsInNonPollActiveState) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_IDLE;
    EXPECT_CALL(*this, nfa_dm_send_deactivate_cmd(_)).Times(0);
    tNFC_STATUS status = nfa_dm_disc_sleep_wakeup();
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_CHECKING, 0);
    EXPECT_FALSE(nfa_dm_cb.disc_cb.deact_pending);
}

TEST_F(NfaDmDiscSleepWakeupTest, HandlesInvalidState) {
    nfa_dm_cb.disc_cb.disc_state = (tNFA_DM_RF_DISC_STATE)999;
    EXPECT_CALL(*this, nfa_dm_send_deactivate_cmd(_)).Times(0);
    tNFC_STATUS status = nfa_dm_disc_sleep_wakeup();
    EXPECT_EQ(status, NFC_STATUS_FAILED);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_CHECKING, 0);
    EXPECT_FALSE(nfa_dm_cb.disc_cb.deact_pending);
}

TEST_F(NfaDmDiscSleepWakeupTest, DoesNothingWhenAlreadyChecking) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_POLL_ACTIVE;
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_CHECKING;
    EXPECT_CALL(*this, nfa_dm_send_deactivate_cmd(testing::_)).Times(0);
    tNFC_STATUS status = nfa_dm_disc_sleep_wakeup();
    EXPECT_TRUE(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_CHECKING);
    EXPECT_FALSE(nfa_dm_cb.disc_cb.deact_pending);
}

TEST_F(NfaDmDiscSleepWakeupTest, DoesNotDeactivateWhenAlreadyChecking) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_POLL_ACTIVE;
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_CHECKING;
    EXPECT_CALL(*this, nfa_dm_send_deactivate_cmd(testing::_)).Times(0);
    tNFC_STATUS status = nfa_dm_disc_sleep_wakeup();
    EXPECT_EQ(status, NFC_STATUS_OK);
    EXPECT_TRUE(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_CHECKING);
    EXPECT_FALSE(nfa_dm_cb.disc_cb.deact_pending);
}

class NfaDmDiscSmDiscoveryTest : public ::testing::Test {
protected:
    void SetUp() override {
        memset(&nfa_dm_cb, 0, sizeof(nfa_dm_cb));
    }
    void TearDown() override {
        memset(&nfa_dm_cb, 0, sizeof(nfa_dm_cb));
    }
    MOCK_METHOD(void, NFC_Deactivate, (tNFC_DEACT_TYPE deactivate_type), ());
    MOCK_METHOD(void, nfa_dm_disc_new_state, (tNFA_DM_RF_DISC_STATE new_state), ());
    MOCK_METHOD(void, nfa_dm_start_rf_discover, (), ());
    MOCK_METHOD(void, nfa_dm_notify_discovery, (tNFA_DM_RF_DISC_DATA* p_data), ());
    MOCK_METHOD(tNFC_STATUS, nfa_dm_disc_notify_activation, (tNFC_DISCOVER* p_data), ());
};

TEST_F(NfaDmDiscSmDiscoveryTest, DeactivateCmdNotSent) {
    nfa_dm_cb.disc_cb.disc_flags &= ~NFA_DM_DISC_FLAGS_W4_RSP;
    EXPECT_CALL(*this, NFC_Deactivate(testing::_)).Times(0);
    tNFA_DM_RF_DISC_DATA data;
    data.deactivate_type = NFA_DEACTIVATE_TYPE_IDLE;
    nfa_dm_disc_sm_discovery(NFA_DM_RF_DEACTIVATE_CMD, &data);
}

TEST_F(NfaDmDiscSmDiscoveryTest, DeactivateCmdAlreadySent) {
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP;
    EXPECT_CALL(*this, NFC_Deactivate(testing::_)).Times(0);
    tNFA_DM_RF_DISC_DATA data;
    nfa_dm_disc_sm_discovery(NFA_DM_RF_DEACTIVATE_CMD, &data);
}

TEST_F(NfaDmDiscSmDiscoveryTest, DeactivateRspNoRaceCondition) {
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP;
    EXPECT_CALL(*this, nfa_dm_disc_new_state(NFA_DM_RFST_IDLE)).Times(0);
    EXPECT_CALL(*this, nfa_dm_start_rf_discover()).Times(0);
    tNFA_DM_RF_DISC_DATA data;
    nfa_dm_disc_sm_discovery(NFA_DM_RF_DEACTIVATE_RSP, &data);
}

TEST_F(NfaDmDiscSmDiscoveryTest, DeactivateRspWithRaceCondition) {
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP | NFA_DM_DISC_FLAGS_W4_NTF;
    EXPECT_CALL(*this, nfa_dm_disc_new_state(NFA_DM_RFST_IDLE)).Times(0);
    EXPECT_CALL(*this, nfa_dm_start_rf_discover()).Times(0);
    tNFA_DM_RF_DISC_DATA data;
    nfa_dm_disc_sm_discovery(NFA_DM_RF_DEACTIVATE_RSP, &data);
}

TEST_F(NfaDmDiscSmDiscoveryTest, InterfaceActivatedNtfRaceCondition) {
    tNFA_DM_RF_DISC_DATA data;
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP;
    EXPECT_CALL(*this, nfa_dm_disc_new_state(NFA_DM_RFST_LISTEN_ACTIVE)).Times(0);
    EXPECT_CALL(*this, nfa_dm_disc_new_state(NFA_DM_RFST_POLL_ACTIVE)).Times(0);
    nfa_dm_disc_sm_discovery(NFA_DM_RF_INTF_ACTIVATED_NTF, &data);
}

class NfaDmDiscSmExecuteTest : public testing::Test {
protected:
    tNFA_DM_RF_DISC_DATA test_data;
    void SetUp() override {
        memset(&nfa_dm_cb, 0, sizeof(nfa_dm_cb));
        memset(&test_data, 0, sizeof(test_data));
        nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_IDLE;
        nfa_dm_cb.disc_cb.disc_flags = 0;
    }
    void TearDown() override {
    }
};

TEST_F(NfaDmDiscSmExecuteTest, IdleStateHandling) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_IDLE;
    nfa_dm_disc_sm_execute(NFA_DM_RF_DEACTIVATE_CMD, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_IDLE);
    EXPECT_FALSE(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_W4_RSP);
}

TEST_F(NfaDmDiscSmExecuteTest, DiscoveryStateHandling) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_DISCOVERY;
    nfa_dm_disc_sm_execute(NFA_DM_RF_DEACTIVATE_RSP, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_IDLE);
    EXPECT_FALSE(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_W4_RSP);
}

TEST_F(NfaDmDiscSmExecuteTest, PollActiveStateHandling) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_POLL_ACTIVE;
    nfa_dm_disc_sm_execute(NFA_DM_RF_DEACTIVATE_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_IDLE);
}

TEST_F(NfaDmDiscSmExecuteTest, ListenActiveStateHandling) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LISTEN_ACTIVE;
    nfa_dm_disc_sm_execute(NFA_DM_RF_INTF_ACTIVATED_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LISTEN_ACTIVE);
}

TEST_F(NfaDmDiscSmExecuteTest, ListenSleepStateHandling) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LISTEN_SLEEP;
    nfa_dm_disc_sm_execute(NFA_DM_RF_DEACTIVATE_CMD, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LISTEN_SLEEP);
}

class NfaDmDiscSmListenActiveTest : public testing::Test {
protected:
    tNFA_DM_RF_DISC_DATA test_data;
    void SetUp() override {
        memset(&nfa_dm_cb, 0, sizeof(nfa_dm_cb));
        memset(&test_data, 0, sizeof(test_data));
        nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LISTEN_ACTIVE;
        nfa_dm_cb.disc_cb.disc_flags = 0;
    }
    void TearDown() override {
    }
};

TEST_F(NfaDmDiscSmListenActiveTest, DeactivateCmdHandling) {
    test_data.deactivate_type = NFC_DEACTIVATE_TYPE_IDLE;
    nfa_dm_disc_sm_listen_active(NFA_DM_RF_DEACTIVATE_CMD, &test_data);
    EXPECT_EQ(nfa_dm_cb.listen_deact_cmd_type, NFC_DEACTIVATE_TYPE_IDLE);
}

TEST_F(NfaDmDiscSmListenActiveTest, DeactivateRspRaceCondition) {
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP;
    nfa_dm_disc_sm_listen_active(NFA_DM_RF_DEACTIVATE_RSP, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_IDLE);
    EXPECT_FALSE(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_W4_RSP);
}

TEST_F(NfaDmDiscSmListenActiveTest, DeactivateNtfRaceCondition) {
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP;
    test_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_IDLE;
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LISTEN_ACTIVE);
    nfa_dm_disc_sm_listen_active(NFA_DM_RF_DEACTIVATE_RSP, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_IDLE);
}

TEST_F(NfaDmDiscSmListenActiveTest, DeactivateNtfNoRspHandling) {
    nfa_dm_cb.disc_cb.disc_flags &= ~NFA_DM_DISC_FLAGS_W4_RSP;
    test_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_IDLE;
    nfa_dm_disc_sm_listen_active(NFA_DM_RF_DEACTIVATE_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_IDLE);
}

TEST_F(NfaDmDiscSmListenActiveTest, DeactivateNtfDiscoveryHandling) {
    nfa_dm_cb.disc_cb.disc_flags &= ~NFA_DM_DISC_FLAGS_W4_RSP;
    test_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_DISCOVERY;
    nfa_dm_disc_sm_listen_active(NFA_DM_RF_DEACTIVATE_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_DISCOVERY);
}

TEST_F(NfaDmDiscSmListenActiveTest, DeactivateNtfSleepHandling) {
    nfa_dm_cb.disc_cb.disc_flags &= ~NFA_DM_DISC_FLAGS_W4_RSP;
    test_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_SLEEP;
    nfa_dm_disc_sm_listen_active(NFA_DM_RF_DEACTIVATE_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LISTEN_SLEEP);
}

TEST_F(NfaDmDiscSmListenActiveTest, DeactivateNtfSleepAFHandling) {
    nfa_dm_cb.disc_cb.disc_flags &= ~NFA_DM_DISC_FLAGS_W4_RSP;
    test_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_SLEEP_AF;
    nfa_dm_disc_sm_listen_active(NFA_DM_RF_DEACTIVATE_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LISTEN_SLEEP);
}

class NfaDmDiscSmListenSleepTest : public ::testing::Test {
protected:
    void SetUp() override {
        memset(&nfa_dm_cb, 0, sizeof(nfa_dm_cb));
        nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LISTEN_SLEEP;
    }
    void TearDown() override {
    }
};

TEST_F(NfaDmDiscSmListenSleepTest, DeactivateCmdHandling) {
    tNFA_DM_RF_DISC_DATA test_data;
    test_data.deactivate_type = NFC_DEACTIVATE_TYPE_IDLE;
    nfa_dm_disc_sm_listen_sleep(NFA_DM_RF_DEACTIVATE_CMD, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LISTEN_SLEEP);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_W4_NTF, 0);
}

TEST_F(NfaDmDiscSmListenSleepTest, DeactivateRspHandling) {
    tNFA_DM_RF_DISC_DATA test_data;
    test_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_IDLE;
    nfa_dm_disc_sm_listen_sleep(NFA_DM_RF_DEACTIVATE_RSP, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_IDLE);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_W4_RSP, 0);
}

TEST_F(NfaDmDiscSmListenSleepTest, DeactivateNtfHandling) {
    tNFA_DM_RF_DISC_DATA test_data;
    test_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_DISCOVERY;
    nfa_dm_disc_sm_listen_sleep(NFA_DM_RF_DEACTIVATE_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_DISCOVERY);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_flags & (
            NFA_DM_DISC_FLAGS_W4_RSP | NFA_DM_DISC_FLAGS_W4_NTF), 0);
}

TEST_F(NfaDmDiscSmListenSleepTest, IntfActivatedNtfHandling) {
    tNFA_DM_RF_DISC_DATA test_data;
    nfa_dm_disc_sm_listen_sleep(NFA_DM_RF_INTF_ACTIVATED_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LISTEN_ACTIVE);
}

TEST_F(NfaDmDiscSmListenSleepTest, UnexpectedEventHandling) {
    tNFA_DM_RF_DISC_DATA test_data;
    nfa_dm_disc_sm_listen_sleep(static_cast<tNFA_DM_RF_DISC_SM_EVENT>(999), &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LISTEN_SLEEP);
}

class NfaDmDiscSmLpActiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        memset(&nfa_dm_cb, 0, sizeof(nfa_dm_cb));
        nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LP_ACTIVE;
    }
    void TearDown() override {
    }

};

TEST_F(NfaDmDiscSmLpActiveTest, ValidDeactivateNtfHandling) {
    tNFA_DM_RF_DISC_DATA test_data = {};
    test_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_DISCOVERY;
    nfa_dm_disc_sm_lp_active(NFA_DM_RF_DEACTIVATE_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LP_LISTEN);
}

TEST_F(NfaDmDiscSmLpActiveTest, UnexpectedEventHandling) {
    tNFA_DM_RF_DISC_DATA test_data = {};
    nfa_dm_disc_sm_lp_active(static_cast<tNFA_DM_RF_DISC_SM_EVENT>(999), &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LP_ACTIVE);
}

TEST_F(NfaDmDiscSmLpActiveTest, MultipleValidDeactivateTypes) {
    tNFA_DM_RF_DISC_DATA test_data = {};
    test_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_DISCOVERY;
    nfa_dm_disc_sm_lp_active(NFA_DM_RF_DEACTIVATE_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LP_LISTEN);
    test_data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_IDLE;
    nfa_dm_disc_sm_lp_active(NFA_DM_RF_DEACTIVATE_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LP_LISTEN);
}

TEST_F(NfaDmDiscSmLpActiveTest, DefaultStateTransitionCheck) {
    tNFA_DM_RF_DISC_DATA test_data = {};
    memset(&test_data, 0, sizeof(test_data));
    nfa_dm_disc_sm_lp_active(static_cast<tNFA_DM_RF_DISC_SM_EVENT>(12345), &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LP_ACTIVE);
}

TEST_F(NfaDmDiscSmLpActiveTest, MinBoundaryEventValue) {
    tNFA_DM_RF_DISC_DATA test_data = {};
    nfa_dm_disc_sm_lp_active(NFA_DM_RF_DEACTIVATE_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LP_LISTEN);
}

TEST_F(NfaDmDiscSmLpActiveTest, MaxBoundaryEventValue) {
    tNFA_DM_RF_DISC_DATA test_data = {};
    memset(&test_data, 0, sizeof(test_data));
    nfa_dm_disc_sm_lp_active(static_cast<tNFA_DM_RF_DISC_SM_EVENT>(0xFFFFFFFF), &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LP_ACTIVE);
}

class NfaDmDiscSmLpListenTest : public ::testing::Test {
protected:
    void SetUp() override {
        memset(&nfa_dm_cb, 0, sizeof(nfa_dm_cb));
        nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LP_LISTEN;
    }
    void TearDown() override {
    }
};

TEST_F(NfaDmDiscSmLpListenTest, ValidIntfActivatedNtfHandlingISO) {
    tNFA_DM_RF_DISC_DATA test_data = {};
    test_data.nfc_discover.activate.intf_param.type = NFC_INTERFACE_ISO_DEP;
    nfa_dm_disc_sm_lp_listen(NFA_DM_RF_INTF_ACTIVATED_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LP_ACTIVE);
}

TEST_F(NfaDmDiscSmLpListenTest, ValidIntfActivatedNtfHandlingNFC) {
    tNFA_DM_RF_DISC_DATA test_data = {};
    test_data.nfc_discover.activate.intf_param.type = NFC_INTERFACE_NFC_DEP;
    nfa_dm_disc_sm_lp_listen(NFA_DM_RF_INTF_ACTIVATED_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LP_ACTIVE);
}

TEST_F(NfaDmDiscSmLpListenTest, UnexpectedEventHandling) {
    tNFA_DM_RF_DISC_DATA test_data = {};
    nfa_dm_disc_sm_lp_listen(static_cast<tNFA_DM_RF_DISC_SM_EVENT>(999), &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LP_LISTEN);
}

TEST_F(NfaDmDiscSmLpListenTest, ValidActivationData) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LP_LISTEN;
    tNFA_DM_RF_DISC_DATA test_data = {};
    test_data.nfc_discover.activate.rf_tech_param.mode = NFC_DISCOVERY_TYPE_POLL_A;
    nfa_dm_disc_sm_lp_listen(NFA_DM_RF_INTF_ACTIVATED_NTF, &test_data);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LP_ACTIVE);
}

TEST_F(NfaDmDiscSmLpListenTest, InvalidEvent) {
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_LP_LISTEN;
    nfa_dm_disc_sm_lp_listen(static_cast<tNFA_DM_RF_DISC_SM_EVENT>(999), nullptr);
    EXPECT_EQ(nfa_dm_cb.disc_cb.disc_state, NFA_DM_RFST_LP_LISTEN);
}

class NfaDmDiscTest : public ::testing::Test {
protected:
    static NfaDMDisc mock_nfa_disc;
    void SetUp() override {
    }
    void TearDown() override {
    }
};

NfaDMDisc NfaDmDiscTest::mock_nfa_disc;

TEST_F(NfaDmDiscTest, HandleDeactivateCmdMifare) {
    tNFA_DM_RF_DISC_DATA data;
    data.deactivate_type = NFC_DEACTIVATE_TYPE_IDLE;
    nfa_dm_cb.disc_cb.activated_protocol = NCI_PROTOCOL_MIFARE;
    nfa_dm_cb.disc_cb.deact_pending = false;
    EXPECT_CALL(mock_nfa_disc, nfa_dm_send_deactivate_cmd(NFA_DM_RF_DEACTIVATE_CMD)).Times(1);
    nfa_dm_disc_sm_poll_active(NFA_DM_RF_DEACTIVATE_CMD, &data);
}

TEST_F(NfaDmDiscTest, HandleDeactivateRspRaceCondition) {
    tNFA_DM_RF_DISC_DATA data;
    data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_IDLE;
    data.nfc_discover.deactivate.reason = NFC_DEACTIVATE_REASON_DH_REQ_FAILED;
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP;
    EXPECT_CALL(mock_nfa_disc, nfa_dm_disc_notify_deactivation(
            NFA_DM_RF_DEACTIVATE_NTF, _)).Times(1);
    EXPECT_CALL(mock_nfa_disc, nfa_dm_disc_new_state(NFA_DM_RFST_IDLE)).Times(1);
    nfa_dm_disc_sm_poll_active(NFA_DM_RF_DEACTIVATE_RSP, &data);
}

TEST_F(NfaDmDiscTest, HandleDeactivateNtfRaceCondition) {
    tNFA_DM_RF_DISC_DATA data;
    data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_IDLE;
    data.nfc_discover.deactivate.reason = NFC_DEACTIVATE_REASON_DH_REQ_FAILED;
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP;
    EXPECT_CALL(mock_nfa_disc, nfa_dm_disc_notify_deactivation(
            NFA_DM_RF_DEACTIVATE_NTF, _)).Times(1);
    nfa_dm_disc_sm_poll_active(NFA_DM_RF_DEACTIVATE_NTF, &data);
}

TEST_F(NfaDmDiscTest, HandleDeactivateNtfSleepWakeup) {
    tNFA_DM_RF_DISC_DATA data;
    data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_SLEEP;
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_CHECKING;
    nfa_dm_cb.disc_cb.deact_pending = true;
    nfa_dm_cb.deactivate_cmd_retry_count = 0;
    EXPECT_CALL(mock_nfa_disc, nfa_dm_disc_end_sleep_wakeup(NFC_STATUS_OK)).Times(1);
    EXPECT_CALL(mock_nfa_disc, NFC_DiscoverySelect(_, _, _)).Times(1);
    nfa_dm_disc_sm_poll_active(NFA_DM_RF_DEACTIVATE_NTF, &data);
}

TEST_F(NfaDmDiscTest, HandleDeactivateCmdRetry) {
    tNFA_DM_RF_DISC_DATA data;
    data.nfc_discover.deactivate.type = NFC_DEACTIVATE_TYPE_SLEEP;
    data.nfc_discover.deactivate.reason = NFC_DEACTIVATE_REASON_DH_REQ_FAILED;
    nfa_dm_cb.deactivate_cmd_retry_count = 2;
    EXPECT_CALL(mock_nfa_disc, nfa_dm_send_deactivate_cmd(NFA_DEACTIVATE_TYPE_SLEEP)).Times(1);
    nfa_dm_disc_sm_poll_active(NFA_DM_RF_DEACTIVATE_NTF, &data);
}

TEST_F(NfaDmDiscTest, HandleWptStartCmdNotEnabled) {
    tNFA_DM_RF_DISC_DATA data;
    data.start_wpt.power_adj_req = 0;
    data.start_wpt.wpt_time_int = 0;
    EXPECT_CALL(mock_nfa_disc, nfa_wlc_event_notify(NFA_WLC_START_WPT_RESULT_EVT, _)).Times(1);
    nfa_dm_disc_sm_poll_active(NFA_DM_WPT_START_CMD, &data);
}

class NfaDmDiscMock {
public:
    MOCK_METHOD(void, NFC_Deactivate, (tNFC_DEACT_TYPE deactivate_type), ());
    MOCK_METHOD(void, nfa_dm_disc_notify_deactivation,(
            tNFA_DM_RF_DISC_SM_EVENT sm_event,tNFC_DISCOVER* p_data));
    MOCK_METHOD(void, nfa_dm_disc_new_state, (tNFA_DM_RF_DISC_STATE new_state));
    MOCK_METHOD(void, nfa_dm_start_rf_discover, (), ());
    MOCK_METHOD(void, nfa_dm_notify_discovery, (tNFA_DM_RF_DISC_DATA* p_data));
    MOCK_METHOD(tNFA_STATUS, nfa_dm_disc_notify_activation, (tNFC_DISCOVER* p_data));
    MOCK_METHOD(tNFC_STATUS, NFC_DiscoverySelect,(uint8_t rf_disc_id, uint8_t protocol,
            uint8_t rf_interface));
    MOCK_METHOD(void, NFC_SetStaticRfCback, (tNFC_CONN_CBACK* p_cback), ());
    MOCK_METHOD(void, nfa_dm_disc_conn_event_notify, (uint8_t event, tNFA_STATUS status), ());
};

class NfaDmDiscW4AllDiscoveriesTest : public ::testing::Test {
protected:
    static NfaDmDiscMock nfa_dm_disc_mock;
    void SetUp() override {
    }
};

NfaDmDiscMock NfaDmDiscW4AllDiscoveriesTest::nfa_dm_disc_mock;

TEST_F(NfaDmDiscW4AllDiscoveriesTest, TestDeactivateCmdNoResponsePending) {
    tNFA_DM_RF_DISC_DATA data;
    memset(&data, 0, sizeof(tNFA_DM_RF_DISC_DATA));
    nfa_dm_cb.disc_cb.disc_flags &= ~NFA_DM_DISC_FLAGS_W4_RSP;
    EXPECT_CALL(nfa_dm_disc_mock, NFC_Deactivate(NFA_DEACTIVATE_TYPE_IDLE)).Times(1);
    nfa_dm_disc_sm_w4_all_discoveries(NFA_DM_RF_DEACTIVATE_CMD, &data);
}

TEST_F(NfaDmDiscW4AllDiscoveriesTest, TestDeactivateRsp) {
    tNFA_DM_RF_DISC_DATA data;
    memset(&data, 0, sizeof(tNFA_DM_RF_DISC_DATA));
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP;
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_disc_notify_deactivation(
            NFA_DM_RF_DEACTIVATE_RSP, &data.nfc_discover)).Times(1);
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_disc_new_state(NFA_DM_RFST_IDLE)).Times(1);
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_start_rf_discover()).Times(1);
    nfa_dm_disc_sm_w4_all_discoveries(NFA_DM_RF_DEACTIVATE_RSP, &data);
}

TEST_F(NfaDmDiscW4AllDiscoveriesTest, TestIntfActivatedNtf) {
    tNFA_DM_RF_DISC_DATA data;
    memset(&data, 0, sizeof(tNFA_DM_RF_DISC_DATA));
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_disc_new_state(NFA_DM_RFST_POLL_ACTIVE)).Times(1);
    EXPECT_CALL(nfa_dm_disc_mock,nfa_dm_disc_notify_activation(
            &data.nfc_discover)).Times(1).WillOnce(testing::Return(NFA_STATUS_OK));
    nfa_dm_disc_sm_w4_all_discoveries(NFA_DM_RF_INTF_ACTIVATED_NTF, &data);
}

TEST_F(NfaDmDiscW4AllDiscoveriesTest, TestDeactivateCmdWithResponseAwaited) {
    tNFA_DM_RF_DISC_DATA data;
    memset(&data, 0, sizeof(tNFA_DM_RF_DISC_DATA));
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP;
    nfa_dm_disc_sm_w4_all_discoveries(NFA_DM_RF_DEACTIVATE_CMD, &data);
}

TEST_F(NfaDmDiscW4AllDiscoveriesTest, TestDiscoverNtfNotLastNotification) {
    tNFA_DM_RF_DISC_DATA data;
    memset(&data, 0, sizeof(tNFA_DM_RF_DISC_DATA));
    data.nfc_discover.result.more = NCI_DISCOVER_NTF_MORE;
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_disc_new_state(NFA_DM_RFST_W4_HOST_SELECT)).Times(1);
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_notify_discovery(&data)).Times(1);
    nfa_dm_disc_sm_w4_all_discoveries(NFA_DM_RF_DISCOVER_NTF, &data);
}

TEST_F(NfaDmDiscW4AllDiscoveriesTest, TestDiscoverNtfLastNotification) {
    tNFA_DM_RF_DISC_DATA data;
    memset(&data, 0, sizeof(tNFA_DM_RF_DISC_DATA));
    data.nfc_discover.result.more = NCI_DISCOVER_NTF_LAST;
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_disc_new_state(NFA_DM_RFST_W4_HOST_SELECT)).Times(1);
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_notify_discovery(&data)).Times(1);
    nfa_dm_disc_sm_w4_all_discoveries(NFA_DM_RF_DISCOVER_NTF, &data);
}

// Tests for nfa_dm_disc_sm_w4_host_select

TEST_F(NfaDmDiscW4AllDiscoveriesTest, TestSelectCmdNoResponseAwaited) {
    tNFA_DM_RF_DISC_DATA data;
    memset(&data, 0, sizeof(tNFA_DM_RF_DISC_DATA));
    nfa_dm_cb.disc_cb.disc_flags &= ~NFA_DM_DISC_FLAGS_W4_RSP;
    EXPECT_CALL(nfa_dm_disc_mock, NFC_DiscoverySelect(
            data.select.rf_disc_id, data.select.protocol, data.select.rf_interface)).Times(1);
    nfa_dm_disc_sm_w4_host_select(NFA_DM_RF_DISCOVER_SELECT_CMD, &data);
}

TEST_F(NfaDmDiscW4AllDiscoveriesTest, TestSelectCmdWithResponseAwaited) {
    tNFA_DM_RF_DISC_DATA data;
    memset(&data, 0, sizeof(tNFA_DM_RF_DISC_DATA));
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP;
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_disc_conn_event_notify(
            NFA_SELECT_RESULT_EVT, NFA_STATUS_FAILED)).Times(1);
    nfa_dm_disc_sm_w4_host_select(NFA_DM_RF_DISCOVER_SELECT_CMD, &data);
}

TEST_F(NfaDmDiscW4AllDiscoveriesTest, TestSelectRspStatusOK) {
    tNFA_DM_RF_DISC_DATA data;
    memset(&data, 0, sizeof(tNFA_DM_RF_DISC_DATA));
    data.nfc_discover.status = NFC_STATUS_OK;
    bool old_sleep_wakeup_flag = false;
    EXPECT_CALL(nfa_dm_disc_mock, NFC_SetStaticRfCback(nfa_dm_disc_data_cback)).Times(1);
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_disc_conn_event_notify(
            NFA_SELECT_RESULT_EVT, NFC_STATUS_OK)).Times(1);
    nfa_dm_disc_sm_w4_host_select(NFA_DM_RF_DISCOVER_SELECT_RSP, &data);
}

TEST_F(NfaDmDiscW4AllDiscoveriesTest, TestDeactivateRspHost) {
    tNFA_DM_RF_DISC_DATA data = {};
    nfa_dm_cb.disc_cb.disc_flags |= NFA_DM_DISC_FLAGS_W4_RSP;
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_disc_conn_event_notify(
            NFA_SELECT_RESULT_EVT, NFC_STATUS_OK)).Times(1);
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_disc_new_state(NFA_DM_RFST_IDLE)).Times(1);
    EXPECT_CALL(nfa_dm_disc_mock, nfa_dm_start_rf_discover()).Times(1);
    nfa_dm_disc_sm_w4_host_select(NFA_DM_RF_DEACTIVATE_RSP, &data);
}

class MockNfaStart {
public:
    MOCK_METHOD(void, nfa_sys_start_timer,(TIMER_LIST_ENT*, uint16_t event, uint16_t timeout), ());
    MOCK_METHOD(tNFC_STATUS, nfa_dm_send_deactivate_cmd, (tNFC_DEACT_TYPE deactivate_type));
};

class NfaDmDiscStartKovioPresenceCheckTest : public testing::Test {
protected:
    static MockNfaStart mock_nfa_start;
    void SetUp() override {
        memset(&nfa_dm_cb, 0, sizeof(nfa_dm_cb));
    }
    void TearDown() override {
    }
};

MockNfaStart NfaDmDiscStartKovioPresenceCheckTest::mock_nfa_start;

TEST_F(NfaDmDiscStartKovioPresenceCheckTest, KovioProtocolActive_TimerInUse_DiscoveryStateActive) {
    nfa_dm_cb.disc_cb.activated_protocol = NFC_PROTOCOL_KOVIO;
    nfa_dm_cb.disc_cb.kovio_tle.in_use = true;
    EXPECT_CALL(mock_nfa_start, nfa_sys_start_timer(
            &nfa_dm_cb.disc_cb.kovio_tle, 0, NFA_DM_DISC_TIMEOUT_KOVIO_PRESENCE_CHECK));
    EXPECT_CALL(mock_nfa_start, nfa_dm_send_deactivate_cmd(
            NFC_DEACTIVATE_TYPE_DISCOVERY)).WillOnce(Return(NFC_STATUS_OK));
    tNFC_STATUS status = nfa_dm_disc_start_kovio_presence_check();
    EXPECT_EQ(status, NFC_STATUS_OK);
    EXPECT_TRUE(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_CHECKING);
    EXPECT_FALSE(nfa_dm_cb.disc_cb.deact_pending);
}

TEST_F(NfaDmDiscStartKovioPresenceCheckTest, KovioProtocolActive_TimerInUse_DiscoveryStateNotActive)
{
    nfa_dm_cb.disc_cb.activated_protocol = NFC_PROTOCOL_KOVIO;
    nfa_dm_cb.disc_cb.kovio_tle.in_use = true;
    nfa_dm_cb.disc_cb.disc_state = NFA_DM_RFST_IDLE;
    EXPECT_CALL(mock_nfa_start, nfa_sys_start_timer(_, _, _)).Times(0);
    EXPECT_CALL(mock_nfa_start, nfa_dm_send_deactivate_cmd(_)).Times(0);
    tNFC_STATUS status = nfa_dm_disc_start_kovio_presence_check();
    EXPECT_EQ(status, NFC_STATUS_OK);
    EXPECT_TRUE(nfa_dm_cb.disc_cb.disc_flags & NFA_DM_DISC_FLAGS_CHECKING);
    EXPECT_FALSE(nfa_dm_cb.disc_cb.deact_pending);
}

TEST_F(NfaDmDiscStartKovioPresenceCheckTest, KovioProtocolActive_TimerNotInUse) {
    nfa_dm_cb.disc_cb.activated_protocol = NFC_PROTOCOL_KOVIO;
    nfa_dm_cb.disc_cb.kovio_tle.in_use = false;
    EXPECT_CALL(mock_nfa_start, nfa_sys_start_timer(_, _, _)).Times(0);
    EXPECT_CALL(mock_nfa_start, nfa_dm_send_deactivate_cmd(_)).Times(0);
    tNFC_STATUS status = nfa_dm_disc_start_kovio_presence_check();
    EXPECT_EQ(status, NFC_STATUS_FAILED);
}

TEST_F(NfaDmDiscStartKovioPresenceCheckTest, NonKovioProtocolActive) {
    nfa_dm_cb.disc_cb.activated_protocol = NFC_PROTOCOL_ISO_DEP;
    EXPECT_CALL(mock_nfa_start, nfa_sys_start_timer(_, _, _)).Times(0);
    EXPECT_CALL(mock_nfa_start, nfa_dm_send_deactivate_cmd(_)).Times(0);
    tNFC_STATUS status = nfa_dm_disc_start_kovio_presence_check();
    EXPECT_EQ(status, NFC_STATUS_FAILED);
}

class NfaDmDiscStateToStrTest : public ::testing::Test {

};

TEST_F(NfaDmDiscStateToStrTest, ReturnsIdleForNFA_DM_RFST_IDLE) {
    EXPECT_EQ(nfa_dm_disc_state_2_str(NFA_DM_RFST_IDLE), "IDLE");
}

TEST_F(NfaDmDiscStateToStrTest, ReturnsDiscoveryForNFA_DM_RFST_DISCOVERY) {
    EXPECT_EQ(nfa_dm_disc_state_2_str(NFA_DM_RFST_DISCOVERY), "DISCOVERY");
}

TEST_F(NfaDmDiscStateToStrTest, ReturnsW4AllDiscoveriesForNFA_DM_RFST_W4_ALL_DISCOVERIES) {
    EXPECT_EQ(nfa_dm_disc_state_2_str(NFA_DM_RFST_W4_ALL_DISCOVERIES), "W4_ALL_DISCOVERIES");
}

TEST_F(NfaDmDiscStateToStrTest, ReturnsW4HostSelectForNFA_DM_RFST_W4_HOST_SELECT) {
    EXPECT_EQ(nfa_dm_disc_state_2_str(NFA_DM_RFST_W4_HOST_SELECT), "W4_HOST_SELECT");
}

TEST_F(NfaDmDiscStateToStrTest, ReturnsPollActiveForNFA_DM_RFST_POLL_ACTIVE) {
    EXPECT_EQ(nfa_dm_disc_state_2_str(NFA_DM_RFST_POLL_ACTIVE), "POLL_ACTIVE");
}

TEST_F(NfaDmDiscStateToStrTest, ReturnsListenActiveForNFA_DM_RFST_LISTEN_ACTIVE) {
    EXPECT_EQ(nfa_dm_disc_state_2_str(NFA_DM_RFST_LISTEN_ACTIVE), "LISTEN_ACTIVE");
}

TEST_F(NfaDmDiscStateToStrTest, ReturnsListenSleepForNFA_DM_RFST_LISTEN_SLEEP) {
    EXPECT_EQ(nfa_dm_disc_state_2_str(NFA_DM_RFST_LISTEN_SLEEP), "LISTEN_SLEEP");
}

TEST_F(NfaDmDiscStateToStrTest, ReturnsLpListenForNFA_DM_RFST_LP_LISTEN) {
    EXPECT_EQ(nfa_dm_disc_state_2_str(NFA_DM_RFST_LP_LISTEN), "LP_LISTEN");
}

TEST_F(NfaDmDiscStateToStrTest, ReturnsLpActiveForNFA_DM_RFST_LP_ACTIVE) {
    EXPECT_EQ(nfa_dm_disc_state_2_str(NFA_DM_RFST_LP_ACTIVE), "LP_ACTIVE");
}

TEST_F(NfaDmDiscStateToStrTest, ReturnsUnknownForInvalidState) {
    EXPECT_EQ(nfa_dm_disc_state_2_str(99), "Unknown");
    EXPECT_EQ(nfa_dm_disc_state_2_str(255), "Unknown");
}

class NfaDmIsRawFrameSessionTest : public ::testing::Test {
protected:
    void SetUp() override {
        nfa_dm_cb.flags = 0;
    }
};

TEST_F(NfaDmIsRawFrameSessionTest, ReturnsTrueWhenRawFrameFlagIsSet) {
    nfa_dm_cb.flags |= NFA_DM_FLAGS_RAW_FRAME;
    EXPECT_TRUE(nfa_dm_is_raw_frame_session());
}

TEST_F(NfaDmIsRawFrameSessionTest, ReturnsFalseWhenRawFrameFlagIsNotSet) {
    nfa_dm_cb.flags &= ~NFA_DM_FLAGS_RAW_FRAME;
    EXPECT_FALSE(nfa_dm_is_raw_frame_session());
}

TEST_F(NfaDmIsRawFrameSessionTest, ReturnsFalseWhenFlagsAreZero) {
    nfa_dm_cb.flags = 0;
    EXPECT_FALSE(nfa_dm_is_raw_frame_session());
}

TEST_F(NfaDmIsRawFrameSessionTest, ReturnsTrueWhenMultipleFlagsIncludeRawFrame) {
    nfa_dm_cb.flags = NFA_DM_FLAGS_RAW_FRAME | 0x02;
    EXPECT_TRUE(nfa_dm_is_raw_frame_session());
}

TEST_F(NfaDmIsRawFrameSessionTest, ReturnsFalseWhenFlagsExcludeRawFrame) {
    nfa_dm_cb.flags = 0x02;
    EXPECT_FALSE(nfa_dm_is_raw_frame_session());
}

class MockNfaNotify {
public:
    MOCK_METHOD(void, nfa_dm_conn_cback_event_notify, (
            tNFA_EE_EVT event,tNFA_CONN_EVT_DATA* p_data), ());
};

class NfaDmNotifyDiscoveryTest : public ::testing::Test {
protected:
    static MockNfaNotify mock_nfa_notify;
    void SetUp() override {
    }
    void TearDown() override {
    }
};

MockNfaNotify NfaDmNotifyDiscoveryTest::mock_nfa_notify;

TEST_F(NfaDmNotifyDiscoveryTest, SendsDiscoveryNotificationWithValidData) {
    tNFA_DM_RF_DISC_DATA input_data{};
    input_data.nfc_discover.result.rf_disc_id = 42;
    EXPECT_CALL(mock_nfa_notify,nfa_dm_conn_cback_event_notify(
            NFA_DISC_RESULT_EVT, testing::_)).WillOnce([](
                    uint8_t event, tNFA_CONN_EVT_DATA* p_data) {
                EXPECT_EQ(event, NFA_DISC_RESULT_EVT);
                ASSERT_NE(p_data, nullptr);
                EXPECT_EQ(p_data->disc_result.status, NFA_STATUS_OK);
                EXPECT_EQ(p_data->disc_result.discovery_ntf.rf_disc_id, 42);
            });
    nfa_dm_notify_discovery(&input_data);
}

TEST_F(NfaDmNotifyDiscoveryTest, HandlesEmptyResultData) {
    tNFA_DM_RF_DISC_DATA input_data{};
    input_data.nfc_discover.result.rf_disc_id = 0;
    EXPECT_CALL(mock_nfa_notify,nfa_dm_conn_cback_event_notify(
            NFA_DISC_RESULT_EVT, testing::_)).WillOnce([](
                    uint8_t event, tNFA_CONN_EVT_DATA* p_data) {
                EXPECT_EQ(event, NFA_DISC_RESULT_EVT);
                ASSERT_NE(p_data, nullptr);
                EXPECT_EQ(p_data->disc_result.status, NFA_STATUS_OK);
                EXPECT_EQ(p_data->disc_result.discovery_ntf.rf_disc_id, 0);
            });
    nfa_dm_notify_discovery(&input_data);
}

TEST_F(NfaDmNotifyDiscoveryTest, SendsDiscoveryNotificationWithMaxData) {
    tNFA_DM_RF_DISC_DATA input_data{};
    input_data.nfc_discover.result.rf_disc_id = 0xFF;
    EXPECT_CALL(mock_nfa_notify,
        nfa_dm_conn_cback_event_notify(NFA_DISC_RESULT_EVT, testing::_)).WillOnce([](
                uint8_t event, tNFA_CONN_EVT_DATA* p_data) {
            EXPECT_EQ(event, NFA_DISC_RESULT_EVT);
            ASSERT_NE(p_data, nullptr);
            EXPECT_EQ(p_data->disc_result.status, NFA_STATUS_OK);
            EXPECT_EQ(p_data->disc_result.discovery_ntf.rf_disc_id, 0xFF);
        });

    nfa_dm_notify_discovery(&input_data);
}

TEST_F(NfaDmNotifyDiscoveryTest, SendsDiscoveryNotificationWithMinData) {
    tNFA_DM_RF_DISC_DATA input_data{};
    input_data.nfc_discover.result.rf_disc_id = 0x00;
    EXPECT_CALL(mock_nfa_notify,
        nfa_dm_conn_cback_event_notify(NFA_DISC_RESULT_EVT, testing::_)).WillOnce([](
                uint8_t event, tNFA_CONN_EVT_DATA* p_data) {
            EXPECT_EQ(event, NFA_DISC_RESULT_EVT);
            ASSERT_NE(p_data, nullptr);
            EXPECT_EQ(p_data->disc_result.status, NFA_STATUS_OK);
            EXPECT_EQ(p_data->disc_result.discovery_ntf.rf_disc_id, 0x00);
        });
    nfa_dm_notify_discovery(&input_data);
}

TEST_F(NfaDmNotifyDiscoveryTest, SendsDiscoveryNotificationWithPartialData) {
    tNFA_DM_RF_DISC_DATA input_data{};
    input_data.nfc_discover.result.rf_disc_id = 0xAB;
    EXPECT_CALL(mock_nfa_notify,
        nfa_dm_conn_cback_event_notify(NFA_DISC_RESULT_EVT, testing::_)).WillOnce([](
                uint8_t event, tNFA_CONN_EVT_DATA* p_data) {
            EXPECT_EQ(event, NFA_DISC_RESULT_EVT);
            ASSERT_NE(p_data, nullptr);
            EXPECT_EQ(p_data->disc_result.status, NFA_STATUS_OK);
            EXPECT_EQ(p_data->disc_result.discovery_ntf.rf_disc_id, 0xAB);
        });
    nfa_dm_notify_discovery(&input_data);
}

TEST_F(NfaDmNotifyDiscoveryTest, VerifiesCallbackEventCorrectness) {
    tNFA_DM_RF_DISC_DATA input_data{};
    input_data.nfc_discover.result.rf_disc_id = 88;
    EXPECT_CALL(mock_nfa_notify,
        nfa_dm_conn_cback_event_notify(testing::Ne(0), testing::_)).WillOnce([](
                uint8_t event, tNFA_CONN_EVT_DATA* p_data) {
            EXPECT_EQ(event, NFA_DISC_RESULT_EVT);
            ASSERT_NE(p_data, nullptr);
            EXPECT_EQ(p_data->disc_result.status, NFA_STATUS_OK);
            EXPECT_EQ(p_data->disc_result.discovery_ntf.rf_disc_id, 88);
        });
    nfa_dm_notify_discovery(&input_data);
}

class MockNfaSendCmd{
public:
    MOCK_METHOD(void, NFC_Deactivate, (tNFC_DEACT_TYPE deactivate_type), ());
    MOCK_METHOD(void, nfa_sys_start_timer, (
            TIMER_LIST_ENT* p_tle, uint16_t type,int32_t timeout), ());
    MOCK_METHOD(tNFC_STATUS, nfa_dm_disc_force_to_idle, (), ());
};

class NfaDmSendDeactivateCmdTest : public ::testing::Test {
protected:
    static MockNfaSendCmd mock_nfa_send_cmd;
    void SetUp() override {
        memset(&nfa_dm_cb, 0, sizeof(nfa_dm_cb));
        nfa_dm_cb.disc_cb.disc_flags = 0;
    }
};

MockNfaSendCmd NfaDmSendDeactivateCmdTest::mock_nfa_send_cmd;

TEST_F(NfaDmSendDeactivateCmdTest, NoFlags_DeactivateCmdSent) {
    uint8_t deactivate_type = NFC_DEACTIVATE_TYPE_DISCOVERY;
    EXPECT_CALL(mock_nfa_send_cmd, NFC_Deactivate(deactivate_type)).WillOnce(testing::Return());
    EXPECT_CALL(mock_nfa_send_cmd, nfa_sys_start_timer(
            testing::NotNull(), 0, NFA_DM_DISC_TIMEOUT_W4_DEACT_NTF)).Times(1);
    tNFC_STATUS result = nfa_dm_send_deactivate_cmd(deactivate_type);
    EXPECT_EQ(result, NFC_STATUS_OK);
}

TEST_F(NfaDmSendDeactivateCmdTest, TimerInUse_DeactivateCmdNotSent) {
    uint8_t deactivate_type = NFC_DEACTIVATE_TYPE_DISCOVERY;
    nfa_dm_cb.disc_cb.tle.in_use = true;
    tNFC_STATUS result = nfa_dm_send_deactivate_cmd(deactivate_type);
    EXPECT_EQ(result, NFC_STATUS_OK);
}

TEST_F(NfaDmSendDeactivateCmdTest, ForceIdle_IfNeeded) {
    nfa_dm_cb.disc_cb.disc_flags = 0;
    nfa_dm_cb.disc_cb.tle.in_use = false;
    EXPECT_CALL(mock_nfa_send_cmd, nfa_dm_disc_force_to_idle()).WillOnce(Return(NFC_STATUS_OK));
    tNFC_STATUS result = nfa_dm_send_deactivate_cmd(NFC_DEACTIVATE_TYPE_DISCOVERY);
    EXPECT_EQ(result, NFC_STATUS_OK);
}

