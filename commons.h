/*
 * Copyright (C) 2009 Yoichi Kawasaki All rights reserved.
 * yk55.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __MOD_INTERVLA_LIMIT_COMMONS_H__
#define __MOD_INTERVLA_LIMIT_COMMONS_H__

#include "httpd.h"
#include "http_log.h"

#define MODTAG "IntervalLimit: "

#define ILLOG_DEBUG(r,args...) ap_log_rerror(APLOG_MARK,APLOG_DEBUG,0,(request_rec*)(r),##args)
#define ILLOG_ERROR(r,args...) ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,(request_rec*)(r),##args)

#endif //__MOD_INTERVLA_LIMIT_COMMONS_H__
