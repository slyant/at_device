#include <rtthread.h>
#include <at_socket_air800.h>
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
			LOG_I("AT_DEVICE_EVT_BASELOC:%s", args);
			break;
		case AT_DEVICE_EVT_GPS:
			LOG_I("AT_DEVICE_EVT_GPS:%s", args);
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
static void at_getip(void)
{
	char* ip = rt_calloc(1,16);
	at_device_control(AT_DEVICE_CMD_IP, RT_NULL, RT_NULL);
	at_device_control(AT_DEVICE_CMD_IP, RT_NULL, ip);
	rt_kprintf("at_getip:%s\r\n", ip);
	rt_free(ip);
}
static void at_getgps(void)
{
	char* gps = rt_calloc(1,128);
	at_device_control(AT_DEVICE_CMD_GPS, RT_NULL, RT_NULL);
	at_device_control(AT_DEVICE_CMD_GPS, RT_NULL, gps);
	rt_kprintf("at_getgps:%s\r\n", gps);
	rt_free(gps);
}
static void at_getloc(void)
{
	char* loc = rt_calloc(1,128);
	at_device_control(AT_DEVICE_CMD_BASELOC, RT_NULL, RT_NULL);
	at_device_control(AT_DEVICE_CMD_BASELOC, RT_NULL, loc);
	rt_kprintf("at_getloc:%s\r\n", loc);
	rt_free(loc);
}
static void at_signal(void)
{
	int signal = 0;
	at_device_control(AT_DEVICE_CMD_SIGNAL, RT_NULL, RT_NULL);
	at_device_control(AT_DEVICE_CMD_SIGNAL, RT_NULL, &signal);
	rt_kprintf("at_signal:%d\r\n", signal);
}
static void at_ttsset(int volume, int mode, int pitch, int speed, int channel)
{
	at_device_cmd_ex_args cmd_ex_args = {0};
	air800_args_tts_set args = {0};
	args.volume = volume;
	args.mode = mode;
	args.pitch = pitch;
	args.speed = speed;
	args.channel = channel;
	cmd_ex_args.cmd_ex_type = AIR800_CMD_TTS_SET;
	cmd_ex_args.cmd_ex_args = &args;
	at_device_control(AT_DEVICE_CMD_EXTENTION, &cmd_ex_args, RT_NULL);
}
static void at_tts(void)
{
	char* text = "���㣬���ֵ";
	at_device_cmd_ex_args cmd_ex_args = {0};
	air800_args_tts_play args = {0};
	args.mode = 2;
	args.text = text;
	cmd_ex_args.cmd_ex_type = AIR800_CMD_TTS_PLAY;
	cmd_ex_args.cmd_ex_args = &args;
	at_device_control(AT_DEVICE_CMD_EXTENTION, &cmd_ex_args, RT_NULL);	
}
static void at_ttsstop(void)
{
	at_device_cmd_ex_args cmd_ex_args = {0};
	cmd_ex_args.cmd_ex_type = AIR800_CMD_TTS_STOP;
	cmd_ex_args.cmd_ex_args = RT_NULL;
	at_device_control(AT_DEVICE_CMD_EXTENTION, &cmd_ex_args, RT_NULL);
}
#ifdef FINSH_USING_MSH
#include <finsh.h>
MSH_CMD_EXPORT_ALIAS(at_power, at_power, control the at device power on/off);
MSH_CMD_EXPORT_ALIAS(at_reset, at_reset, control the at device reset);
MSH_CMD_EXPORT_ALIAS(at_init, at_init, control the at device initialization);
MSH_CMD_EXPORT_ALIAS(at_getip, at_getip, get the at device ip address);
MSH_CMD_EXPORT_ALIAS(at_getgps, at_getgps, get the at device gps);
MSH_CMD_EXPORT_ALIAS(at_getloc, at_getloc, get the at device base location);
MSH_CMD_EXPORT_ALIAS(at_signal, at_signal, get the at device signal strength);
MSH_CMD_EXPORT_ALIAS(at_tts, at_tts, control the at device TTS play);
MSH_CMD_EXPORT_ALIAS(at_ttsstop, at_ttsstop, control the at device TTS stop);
FINSH_FUNCTION_EXPORT_ALIAS(at_ttsset, at_ttsset, control the at device TTS setup);
#endif

static int at_device_sample(void)
{
	at_device_set_event_cb(AT_DEVICE_EVT_ALL, at_event_callback);
	return RT_EOK;
}
INIT_APP_EXPORT(at_device_sample);
