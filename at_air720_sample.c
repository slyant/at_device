/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018-11-17     slyant	first version
 */
#include <rtthread.h>
#include <at_socket_air720.h>
#include <at_device.h>
#define LOG_TAG              "AT_DEVICE_SAMPLE"
#include <at_log.h>

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
	rt_thread_mdelay(1000);
	at_device_control(AT_DEVICE_CMD_IP, RT_NULL, ip);
	rt_kprintf("at_getip:%s\r\n", ip);
	rt_free(ip);
}
static void at_getloc(void)
{
	char* loc = rt_calloc(1,128);
	at_device_control(AT_DEVICE_CMD_BASELOC, RT_NULL, RT_NULL);
	rt_thread_mdelay(1000);
	at_device_control(AT_DEVICE_CMD_BASELOC, RT_NULL, loc);
	rt_kprintf("at_getloc:%s\r\n", loc);
	rt_free(loc);
}
static void at_signal(void)
{
	int signal = 0;
	at_device_control(AT_DEVICE_CMD_SIGNAL, RT_NULL, RT_NULL);
	rt_thread_mdelay(1000);
	at_device_control(AT_DEVICE_CMD_SIGNAL, RT_NULL, &signal);
	rt_kprintf("at_signal:%d\r\n", signal);
}

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
			at_ttsset(90,1,50,60,0);
			at_tts_play("连接成功");
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

extern int get_weather(int argc, char **argv);
static void getip_thread_entry(void* parameter)
{
	static int get_count = 0;
	while(1)
	{
		rt_thread_mdelay(1000*60*5);
		do
		{
			char* text = rt_calloc(1,128);
			get_weather(1, RT_NULL);
			if(at_device_control(AT_DEVICE_CMD_IP, RT_NULL, RT_NULL)!=RT_EOK)
			{
				
				sprintf(text, "获取IP失败:%d", get_count++);
			}
			else
			{
				sprintf(text, "获取IP成功:%d", get_count++);
			}
			at_tts_play(text);
			rt_free(text);
		}while(0);
	}
}

static int at_device_sample(void)
{
	rt_thread_t  getip_thread = rt_thread_create("getip", 
							getip_thread_entry,  RT_NULL,
							10240,
							10,	10);
	if(getip_thread!=RT_NULL)
		rt_thread_startup(getip_thread);
	
	at_device_set_event_cb(AT_DEVICE_EVT_ALL, at_event_callback);	

	return RT_EOK;
}
//INIT_APP_EXPORT(at_device_sample);
