#ifndef __AT_DEVICE_H__
#define __AT_DEVICE_H__

typedef enum
{
    AT_DEVICE_EVT_AT_CONN_OK,		//AT设备连接成功
	AT_DEVICE_EVT_AT_CONN_FAIL,		//AT设备连接失败
	AT_DEVICE_EVT_NET_REG_OK,		//运营商网络注册成功
	AT_DEVICE_EVT_NET_REG_FAIL,		//运营商网络注册失败
	AT_DEVICE_EVT_NET_REG_DENY,		//运营商网络注册被拒绝(网络业务被禁用)
	AT_DEVICE_EVT_NET_CONN_OK,		//运营商网络连接成功
	AT_DEVICE_EVT_NET_CONN_FAIL,	//运营商网络连接失败
	AT_DEVICE_EVT_SIGNAL_STRENGTH,	//信号强度百分比
	AT_DEVICE_EVT_IP_ADDRESS,		//IP地址
	AT_DEVICE_EVT_GSMLOC,			//基站定位信息
	AT_DEVICE_EVT_GPS,				//GPS定位信息
	AT_DEVICE_EVT_EXTENTION,		//其它事件扩展
	AT_DEVICE_EVT_COUNT
}at_device_evt_t;

typedef void (*at_device_evt_cb_t)(at_device_evt_t event, void* args);

void at_device_set_event_cb(at_device_evt_t event, at_device_evt_cb_t cb);
void at_device_control(const char* cmd, void* args);

#endif
