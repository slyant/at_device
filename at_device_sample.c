#include <rtthread.h>
#include <at_device.h>
#define LOG_TAG              "AT_DEVICE_SAMPLE"
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
			LOG_I("AT_DEVICE_EVT_NET_REG_OK(%d)", args);
			break;
		case AT_DEVICE_EVT_NET_REG_FAIL:
			LOG_I("AT_DEVICE_EVT_NET_REG_FAIL(%d)", args);
			break;
		case AT_DEVICE_EVT_NET_REG_DENY:
			LOG_I("AT_DEVICE_EVT_NET_REG_DENY");
			break;
		case AT_DEVICE_EVT_NET_CONN_OK:
			LOG_I("AT_DEVICE_EVT_NET_CONN_OK,IP:%s", args);
			break;
		case AT_DEVICE_EVT_NET_CONN_FAIL:
			LOG_I("AT_DEVICE_EVT_NET_CONN_FAIL");
			break;
		case AT_DEVICE_EVT_IP_ADDRESS:
			LOG_I("AT_DEVICE_EVT_IP_ADDRESS:%s", args);
			break;
		case AT_DEVICE_EVT_SIGNAL_STRENGTH:
			LOG_I("AT_DEVICE_EVT_SIGNAL_STRENGTH(%d)", args);
			break;
		case AT_DEVICE_EVT_BASELOC:
			break;
		case AT_DEVICE_EVT_GPS:
			break;
		case AT_DEVICE_EVT_EXTENTION:
			break;
		default:break;
	}	
}
static void at_power(void)
{
	at_device_control(AT_DEVICE_CMD_POWER, RT_NULL, RT_NULL);
}
static void at_reset(void)
{
	at_device_control(AT_DEVICE_CMD_RESET, RT_NULL, RT_NULL);
}
static void at_init(void)
{
	at_device_control(AT_DEVICE_CMD_INIT_NET, RT_NULL, RT_NULL);
}
static void at_ip(void)
{
	char* ip = rt_calloc(1,16);
	at_device_control(AT_DEVICE_CMD_IP, RT_NULL, RT_NULL);
	at_device_control(AT_DEVICE_CMD_IP, RT_NULL, ip);
	rt_kprintf("at_ip:%s\r\n", ip);
	rt_free(ip);
}
static void at_sig(void)
{
	int signal = 0;
	at_device_control(AT_DEVICE_CMD_SIGNAL, RT_NULL, RT_NULL);
	at_device_control(AT_DEVICE_CMD_SIGNAL, RT_NULL, &signal);
	rt_kprintf("at_sig:%d\r\n", signal);
}

#ifdef FINSH_USING_MSH
#include <finsh.h>
MSH_CMD_EXPORT_ALIAS(at_power, at_power, control the at device power on/off);
MSH_CMD_EXPORT_ALIAS(at_reset, at_reset, control the at device reset);
MSH_CMD_EXPORT_ALIAS(at_init, at_init, control the at device initialization);
MSH_CMD_EXPORT_ALIAS(at_ip, at_ip, get the at device ip address);
MSH_CMD_EXPORT_ALIAS(at_sig, at_sig, get the at device signal strength);
#endif

static int at_device_sample(void)
{
	at_device_set_event_cb(AT_DEVICE_EVT_ALL, at_event_callback);
	return RT_EOK;
}
INIT_APP_EXPORT(at_device_sample);
