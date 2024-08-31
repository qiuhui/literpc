/*
 * File: msg.h
 * File Created: Tuesday, 18th June 2024 10:09:35 am
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Tuesday, 18th June 2024 10:09:38 am
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */

#ifndef MSG_H
#define MSG_H

#if defined(__cplusplus)
extern "C" {
#endif  // __cplusplus


typedef enum {
    /* 系统业务消息码 */

    //固件升级
    RPC_SYS_FIRMWARE_UPGRADE_REQ = 0x0100,
    RPC_SYS_FIRMWARE_UPGRADE_RESP = 0x0101,
    //模型升级
    RPC_SYS_AIMODEL_UPGRADE_REQ = 0x0102,
    RPC_SYS_AIMODEL_UPGRADE_RESP = 0x0103,
    //摄像头异常通知
    RPC_SYS_SENSOR_ABNORMAL_NOTIFY = 0x0104,
    RPC_SYS_SENSOR_ABNORMAL_NOTIFY_RESP = 0x0105,
    //前锁重启通知
    RPC_SYS_REBOOT_NOTIFY = 0x0106,
    RPC_SYS_REBOOT_NOTIFY_RESP = 0x0107,

    /* 音频业务消息码 */
    RPC_AUDIO_START_CAPTURE_REQ = 0x0200,
    RPC_AUDIO_START_CAPTURE_RESP = 0x0201,
    RPC_AUDIO_STOP_CAPTURE_REQ = 0x0202,
    RPC_AUDIO_STOP_CAPTURE_RESP = 0x0203,
    RPC_AUDIO_SET_PLAY_PARAMETER_REQ = 0x0204,
    RPC_AUDIO_SET_PLAY_PARAMETER_RESP = 0x0205,
    RPC_AUDIO_SET_PLAY_VOLUME_REQ = 0x0206,
    RPC_AUDIO_SET_PLAY_VOLUME_RESP = 0x0207,

    /* 视频业务消息码 */
    RPC_VIDEO_IFRAME_REQ = 0x0300,
    RPC_VIDEO_IFRAME_RESP = 0x0301,
    RPC_VIDEO_SET_BITRATE_REQ = 0x0302,
    RPC_VIDEO_SET_BITRATE_RESP = 0x0303,
    RPC_VIDEO_CREATE_PEDESTRIAN_DETECT_TASK_REQ = 0x0304,
    RPC_VIDEO_CREATE_PEDESTRIAN_DETECT_TASK_RESP = 0x0305,
    RPC_VIDEO_PEDESTRIAN_DETECT_NOTIFY_REQ = 0x0306,
    RPC_VIDEO_PEDESTRIAN_DETECT_NOTIFY_RESP = 0x0307,
    RPC_VIDEO_PEDESTRIAN_DETECT_IMAGE_SEND_REQ = 0x0308,
    RPC_VIDEO_PEDESTRIAN_DETECT_IMAGE_SEND_RESP = 0x0309,
} sophon_rpc_msg_e;

#if defined(__cplusplus)
}
#endif  // __cplusplus

#endif



