#include <rtthread.h>
#include <at_device.h>

at_device_evt_cb_t at_dev_evt_cb_set[AT_DEVICE_EVT_ALL] = {0};
at_device_control_t at_device_control_point = RT_NULL;
/**
 * set AT device event callback
 *
 * @param callback event
 * @param event callback
 */
void at_device_set_event_cb(at_device_evt_t event, at_device_evt_cb_t cb)
{
	/*
	If event is AT_DEVICE_EVT_ALL, all events will be set to the same callback function(cb).
	*/
	rt_uint8_t i;
	if(event==AT_DEVICE_EVT_ALL)
	{
		for(i=0;i< AT_DEVICE_EVT_ALL;i++)
		{
			at_dev_evt_cb_set[i] = cb;
		}	
	}
	else
	{ 
		i = (rt_uint8_t)event;
		if(i< AT_DEVICE_EVT_ALL)
			at_dev_evt_cb_set[i] = cb;
	}
}
/**
 * set AT device control handler
 *
 * @param control handler
 */
void at_device_set_control(at_device_control_t at_device_control)
{
	at_device_control_point = at_device_control;
}
/**
 * AT device event callback
 *
 * @param callback event
 * @param callback args
 */
void at_device_event_callback(at_device_evt_t event, void* args)
{
	rt_uint8_t i = (rt_uint8_t)event;
	if(i< AT_DEVICE_EVT_ALL && at_dev_evt_cb_set[i])
		at_dev_evt_cb_set[i](event, args);
}

/**
 * AT device control
 *
 * @param control command
 * @param command args
 */
int at_device_control(at_device_cmd_t cmd, void* in_args, void* out_result)
{
	if(at_device_control_point)
		return at_device_control_point(cmd, in_args, out_result);
	return RT_EEMPTY;
	/*
	You can selectively implement some functions of this function in porting.
	
	int result = RT_EOK;
	switch(cmd)
	{
		case AT_DEVICE_CMD_POWER:			
			break;
		case AT_DEVICE_CMD_RESET:
			break;
		case AT_DEVICE_CMD_INIT_NET:
			break;
		case AT_DEVICE_CMD_LOW_POWER:
			break;
		case AT_DEVICE_CMD_SLEEP:
			break;
		case AT_DEVICE_CMD_WAKEUP:
			break;
		case AT_DEVICE_CMD_IP:
			break;
		case AT_DEVICE_CMD_SIGNAL:
			break;
		case AT_DEVICE_CMD_BASELOC:
			break;
		case AT_DEVICE_CMD_GPS:
			break;
		case AT_DEVICE_CMD_EXTENTION:
			break;
		default:break;
	}
	return result;
	*/
}
