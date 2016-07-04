#!/usr/bin/env python

import os
import sys
import re
import logging
import json
import traceback
import time

cdir = os.path.abspath(os.path.dirname(__file__))


settings = {
    "logfile_path": "/var/log/asterisk/inbound_extsecurity.log",
    "default_sleep_protection_time_sec": 2,
    "alert_if_callerid_num_is_not_numeric": True,
    "alert_if_dialed_exten_is_not_numeric": True,
    "alert_if_dialed_exten_lenghts_less_than": 10,
    "alert_if_dialed_exten_lenghts_more_than": 14,
    "automatic_block_attempts_to_extensions": [ 
	ur"\d{1,3}",  
    ],
}

if __name__ == "__main__":

    pt = settings["default_sleep_protection_time_sec"] \
	if "default_sleep_protection_time_sec" in settings and settings["default_sleep_protection_time_sec"] > 0 \
	else 0

    logging.basicConfig(
	format="%(asctime)s.%(msecs)03d %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.NOTSET,
	filename=settings["logfile_path"],
    )

    log = logging.getLogger()

    try:
	json_in = " ".join(sys.argv[1:])
	json_in = json.loads(json_in)
    except:
	json_in = " ".join(sys.argv[1:])
	log.critical("Request line: {}".format(json_in))
	log.critical(traceback.format_exc().strip())
	sys.exit(-1)

    callee_ip = json_in["ip"] if "ip" in json_in else ""
    callerid_num = json_in["callerid_num"] if "callerid_num" in json_in else ""
    callerid_name = json_in["callerid_name"] if "callerid_name" in json_in else ""
    dest_exten = json_in["dest_exten"] if "dest_exten" in json_in else ""
    user_agent = json_in["user_agent"] if "user_agent" in json_in else ""
    peer_name = json_in["peer_name"] if "peer_name" in json_in else ""

    # Warn if callerid number is not numeric
    if "alert_if_callerid_num_is_not_numeric" in settings and settings["alert_if_callerid_num_is_not_numeric"] and \
	(callerid_num is None or callerid_num.strip() == "" or not callerid_num.strip().replace("+", "").isdigit()):
	log.error("ip={} reason=wrong_callerid_num callerid_num={} callerid_name='{}' dest_exten='{}' peer_name='{}' user_agent='{}'".format(callee_ip, callerid_num, callerid_name, dest_exten, peer_name, user_agent))
	time.sleep(pt)
	sys.exit(0)

    # Check if called extension is not numeric
    if "alert_if_dialed_exten_is_not_numeric" in settings and settings["alert_if_dialed_exten_is_not_numeric"] and \
	(callerid_num is None or callerid_num.strip() == "" or not dest_exten.strip().replace("+", "").isdigit()):
	log.error("ip={} reason=wrong_exten_type callerid_num={} callerid_name='{}' dest_exten='{}' peer_name='{}' user_agent='{}'".format(callee_ip, callerid_num, callerid_name, dest_exten, peer_name, user_agent))
	time.sleep(pt)
	sys.exit(0)

    # Check for called minimal number lenghts
    if "alert_if_dialed_exten_lenghts_less_than" in settings and settings["alert_if_dialed_exten_lenghts_less_than"] > 0 and \
	len(dest_exten) < settings["alert_if_dialed_exten_lenghts_less_than"]:
	log.error("ip={} reason=wrong_exten_min_lenghts({}) callerid_num={} callerid_name='{}' dest_exten='{}' peer_name='{}' user_agent='{}'".format(callee_ip, len(dest_exten), callerid_num, callerid_name, dest_exten, peer_name, user_agent))
	time.sleep(pt)
	sys.exit(0)

    # Check for called maximum number lenghts
    if "alert_if_dialed_exten_lenghts_more_than" in settings and settings["alert_if_dialed_exten_lenghts_more_than"] > 0 and \
	len(dest_exten) > settings["alert_if_dialed_exten_lenghts_more_than"]:
	log.error("ip={} reason=wrong_exten_max_lenghts({}) callerid_num={} callerid_name='{}' dest_exten='{}' peer_name='{}' user_agent='{}'".format(callee_ip, len(dest_exten), callerid_num, callerid_name, dest_exten, peer_name, user_agent))
	time.sleep(pt)
	sys.exit(0)

    # Check if called extension in automatic black list
    if "automatic_block_attempts_to_extensions" in settings and isinstance(settings["automatic_block_attempts_to_extensions"], list):
	for ban_pattern in settings["automatic_block_attempts_to_extensions"]:
	    if re.match(ban_pattern, dest_exten):
		log.error("ip={} reason=exension_banned callerid_num={} callerid_name='{}' dest_exten='{}' peer_name='{}' user_agent='{}'".format(callee_ip, callerid_num, callerid_name, dest_exten, peer_name, user_agent))
		time.sleep(pt)
		sys.exit(0)


    log.info("ip={} reason=ok callerid_num={} callerid_name='{}' dest_exten='{}' peer_name='{}' user_agent='{}'".format(callee_ip, callerid_num, callerid_name, dest_exten, peer_name, user_agent))
    sys.exit(0)


