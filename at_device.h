/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018-10-27     slyant	first version
 */
#ifndef __AT_DEVICE_H__
#define __AT_DEVICE_H__

typedef struct
{
	int cmd_ex_type;
	void* cmd_ex_args;
}at_device_cmd_ex_args, *at_device_cmd_ex_args_t;	//扩展命令参数类型

typedef enum
{
    AT_DEVICE_EVT_AT_CONN_OK,		//AT设备连接成功
	AT_DEVICE_EVT_AT_CONN_FAIL,		//AT设备连接失败
	AT_DEVICE_EVT_NET_REG_OK,		//网络注册成功
	AT_DEVICE_EVT_NET_REG_FAIL,		//网络注册失败
	AT_DEVICE_EVT_NET_REG_DENY,		//网络注册被拒绝(网络业务被禁用)
	AT_DEVICE_EVT_NET_CONN_OK,		//网络连接成功
	AT_DEVICE_EVT_NET_CONN_FAIL,	//网络连接失败
	AT_DEVICE_EVT_IP_ADDRESS,		//IP地址
	AT_DEVICE_EVT_SIGNAL_STRENGTH,	//信号强度百分比
	AT_DEVICE_EVT_BASELOC,			//基站定位信息
	AT_DEVICE_EVT_GPS,				//GPS定位信息
	AT_DEVICE_EVT_EXTENTION,		//其它扩展事件
	AT_DEVICE_EVT_ALL
}at_device_evt_t;

typedef enum
{
	AT_DEVICE_CMD_EXTENTION,		//扩展命令
	AT_DEVICE_CMD_POWER,			//控制电源
	AT_DEVICE_CMD_RESET,			//控制复位
	AT_DEVICE_CMD_INIT_NET,			//初始化网络连接
	AT_DEVICE_CMD_LOW_POWER,		//进入低功耗
	AT_DEVICE_CMD_SLEEP,			//进入休眠
	AT_DEVICE_CMD_WAKEUP,			//唤醒
	AT_DEVICE_CMD_IP,				//获取IP地址
	AT_DEVICE_CMD_SIGNAL,			//获取信号强度百分比
	AT_DEVICE_CMD_BASELOC,			//获取基站定位信息
	AT_DEVICE_CMD_GPS,				//获取GPS定位信息
}at_device_cmd_t;

typedef void (*at_device_evt_cb_t)(at_device_evt_t event, void* args);
typedef int (*at_device_control_t)(at_device_cmd_t cmd, void* in_args, void* out_result);

void at_device_set_event_cb(at_device_evt_t event, at_device_evt_cb_t cb);
void at_device_set_control(at_device_control_t at_device_control);
void at_device_event_callback(at_device_evt_t event, void* args);
int at_device_control(at_device_cmd_t cmd, void* in_args, void* out_result);

#endif
