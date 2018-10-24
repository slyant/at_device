#include <rtthread.h>
#include <at_device.h>
#define LOG_TAG              "SAMPLE"
#include <at_log.h>

static void at_event_callback(at_device_evt_t event, void* args)
{
	rt_uint8_t e = (rt_uint8_t)event;
	switch(e)
	{
		case AT_DEVICE_EVT_AT_CONN_OK:
			LOG_I("AT_DEVICE_EVT_AT_CONN_OK");
			break;
		case AT_DEVICE_EVT_AT_CONN_FAIL:
			LOG_I("AT_DEVICE_EVT_AT_CONN_FAIL");
			break;
		case AT_DEVICE_EVT_NET_REG_OK:
			LOG_I("AT_DEVICE_EVT_NET_REG_OK");
			break;
		case AT_DEVICE_EVT_NET_REG_FAIL:
			LOG_I("AT_DEVICE_EVT_NET_REG_FAIL:%d", args);
			break;
		case AT_DEVICE_EVT_NET_REG_DENY:
			LOG_I("AT_DEVICE_EVT_NET_REG_DENY");
			break;
		case AT_DEVICE_EVT_NET_CONN_OK:
			LOG_I("AT_DEVICE_EVT_NET_CONN_OK");
			break;
		case AT_DEVICE_EVT_NET_CONN_FAIL:
			LOG_I("AT_DEVICE_EVT_NET_CONN_FAIL");
			break;
		case AT_DEVICE_EVT_SIGNAL_STRENGTH:
			LOG_I("AT_DEVICE_EVT_SIGNAL_STRENGTH:%d", args);
			break;
		case AT_DEVICE_EVT_IP_ADDRESS:
			LOG_I("AT_DEVICE_EVT_IP_ADDRESS:%s", args);
			break;
		case AT_DEVICE_EVT_GSMLOC:
			break;
		case AT_DEVICE_EVT_GPS:
			break;
		case AT_DEVICE_EVT_EXTENTION:
			break;
		default:break;
	}	
}

static int at_air800_sample(void)
{
	at_device_set_event_cb(AT_DEVICE_EVT_COUNT, at_event_callback);
	return RT_EOK;
}
INIT_APP_EXPORT(at_air800_sample);
