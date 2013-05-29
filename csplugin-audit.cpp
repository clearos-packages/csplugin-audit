// ClearSync: Audit plugin.
// Copyright (C) 2011 ClearFoundation <http://www.clearfoundation.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <sstream>

#include <unistd.h>
#include <fcntl.h>

#define _GNU_SOURCE 1

#include <pwd.h>

#include <clearsync/csplugin.h>
#include <clearsync/csnetlink.h>

#ifndef _CSPLUGIN_AUDIT_JSON
#define _CSPLUGIN_AUDIT_JSON    "/var/clearos/framework/tmp/audit.json"
#endif

#define _MIN_UID                500
#define _MAX_UID                65535

class csPluginConf;
class csPluginXmlParser : public csXmlParser
{
public:
    virtual void ParseElementOpen(csXmlTag *tag);
    virtual void ParseElementClose(csXmlTag *tag);
};

class csPluginAudit;
class csPluginConf : public csConf
{
public:
    csPluginConf(csPluginAudit *parent,
        const char *filename, csPluginXmlParser *parser)
        : csConf(filename, parser), parent(parent) { };

    virtual void Reload(void);

protected:
    friend class csPluginXmlParser;

    csPluginAudit *parent;
};

void csPluginConf::Reload(void)
{
    csConf::Reload();
    parser->Parse();
}

struct csAuditSample {
    unsigned long users;
    unsigned long mac;
    unsigned long ipv4;
    unsigned long ipv6;
    unsigned long interval;
};

struct csAuditTask {
    struct csAuditSample *sample;
    map<string, unsigned long> mac_index;
    map<string, unsigned long> ipv4_index;
    map<string, unsigned long> ipv6_index;
};
    
class csPluginAudit : public csPlugin
{
public:
    csPluginAudit(const string &name,
        csEventClient *parent, size_t stack_size);
    virtual ~csPluginAudit();

    virtual void SetConfigurationFile(const string &conf_filename);

    virtual void *Entry(void);

protected:
    friend class csPluginXmlParser;

    csPluginConf *conf;

    uid_t minuid;
    uid_t maxuid;

    map<csTimer *, string> timer;
    map<string, struct csAuditSample *> sample;

    static cstimer_id_t timer_id;

    cstimer_id_t GenerateTimerId(void) {
        cstimer_id_t id;
        csCriticalSection::Lock();
        timer_id += 100;
        id = timer_id;
        csCriticalSection::Unlock();
        return id;
    };

    unsigned long GetUserCount(void);

private:
    char *pwent_buffer;
    long pwent_buffer_len;
    long neighbors;

    void ProcessTimerEvent(csEventTimer *event);
    void ProcessNetlinkEvent(csEventNetlink *event);
    void SaveTaskResult(struct csAuditTask *task);
};

cstimer_id_t csPluginAudit::timer_id = 0;

csPluginAudit::csPluginAudit(const string &name,
    csEventClient *parent, size_t stack_size)
    : csPlugin(name, parent, stack_size),
    conf(NULL), minuid(_MIN_UID), maxuid(_MAX_UID)
{
    pwent_buffer_len = ::csGetPageSize();
    pwent_buffer = new char[pwent_buffer_len];

    csLog::Log(csLog::Debug, "%s: Initialized.", name.c_str());
}

csPluginAudit::~csPluginAudit()
{
    Join();

    map<csTimer *, string>::iterator ti;
    map<string, struct csAuditSample *>::iterator i;

    for (ti = timer.begin(); ti != timer.end(); ti++) {
        i = sample.find(ti->second);
        if (i == sample.end()) continue;

        i->second->interval = (unsigned long)ti->first->GetRemaining();
        SetStateVar(i->first,
            sizeof(struct csAuditSample), (uint8_t *)i->second);
    }

    for (ti = timer.begin();
        ti != timer.end(); ti++) delete ti->first;
    for (i = sample.begin(); i != sample.end(); i++) delete i->second;

    if (pwent_buffer) delete [] pwent_buffer;
    if (conf) delete conf;
}

void csPluginAudit::SetConfigurationFile(const string &conf_filename)
{
    if (conf == NULL) {
        csPluginXmlParser *parser = new csPluginXmlParser();
        conf = new csPluginConf(this, conf_filename.c_str(), parser);
        parser->SetConf(dynamic_cast<csConf *>(conf));
        conf->Reload();
    }
}

void *csPluginAudit::Entry(void)
{
    map<csTimer *, string>::iterator it;
    map<string, struct csAuditSample *>::iterator i;

    for (i = sample.begin(); i != sample.end(); i++) {
        size_t length = sizeof(struct csAuditSample);
        if (GetStateVar(i->first,
            length, (uint8_t *)i->second) == false)
            continue;
#if 0
        csLog::Log(csLog::Debug, "%s: Loaded: \"%s\", length: %lu",
            name.c_str(), i->first.c_str(), length);
        ::csHexDump(stdout, i->second, length);
#endif
        for (it = timer.begin(); it != timer.end(); it++) {
            if (it->second != i->first) continue;
            it->first->SetValue(i->second->interval);
            break;
        }
    }

    for (it = timer.begin(); it != timer.end(); it++)
        it->first->Start();

    for ( ;; ) {
        csEvent *event = EventPopWait();

        switch (event->GetId()) {
        case csEVENT_QUIT:
            delete event;
            return NULL;

        case csEVENT_TIMER:
            ProcessTimerEvent(static_cast<csEventTimer *>(event));
            delete event;
            break;

        case csEVENT_NETLINK:
            ProcessNetlinkEvent(static_cast<csEventNetlink *>(event));
            // XXX: Don't delete the event from here, done from within
            // ProcessNetlinkEvent().
            break;

        default:
            delete event;
            break;
        }
    }

    // XXX: Never reached...
    return NULL;
}

unsigned long csPluginAudit::GetUserCount(void)
{
    struct passwd pw, *pwp;
    unsigned long users = 0;

    setpwent();

    for ( ;; ) {
        if (getpwent_r(&pw, pwent_buffer, pwent_buffer_len, &pwp)) break;
        if (pwp->pw_uid < minuid || pwp->pw_uid > maxuid) continue; 
        users++;
    }

    endpwent();

    return users;
}

void csPluginAudit::ProcessTimerEvent(csEventTimer *event)
{
    map<csTimer *, string>::iterator i;
    i = timer.find(event->GetTimer());
    if (i == timer.end()) throw csException(ENOENT, "timer");

    map<string, struct csAuditSample *>::iterator is;
    is = sample.find(i->second);
    if (is == sample.end()) throw csException(ENOENT, "sample");

    struct csAuditTask *task = new struct csAuditTask;
    task->sample = is->second;

    neighbors = 0;
    csEventNetlink *netlink_event;
    netlink_event = new csEventNetlink(
        csEventNetlink::NL_Query, RTM_GETNEIGH);
    netlink_event->SetUserData((void *)task);

    csThreadNetlink *netlink_thread = csThreadNetlink::GetInstance();
    EventDispatch(netlink_event, netlink_thread);
}

void csPluginAudit::ProcessNetlinkEvent(csEventNetlink *event)
{
    size_t length;
    struct nlmsghdr *nh;
    struct ndmsg *ndh;
    struct rtattr *rtah;
    char ip[INET6_ADDRSTRLEN];
    struct csAuditTask *task = (struct csAuditTask *)event->GetUserData();
    map<string, unsigned long>::iterator i;

    while ((nh = event->GetReply()) != NULL) {

        switch (nh->nlmsg_type) {

        case RTM_NEWNEIGH:
            ndh = (struct ndmsg *)NLMSG_DATA(nh);
#if 0
            csLog::Log(csLog::Debug, "%s: New neighbor, family: 0x%02x, "
                "ifindex: 0x%08x, state: 0x%04x, flags: 0x%02x, type: 0x%02x",
                name.c_str(),
                ndh->ndm_family, ndh->ndm_ifindex,
                ndh->ndm_state, ndh->ndm_flags,
                ndh->ndm_type);
#endif
            if (!(ndh->ndm_state & NUD_REACHABLE) &&
                !(ndh->ndm_state & NUD_STALE) &&
                !(ndh->ndm_state & NUD_PERMANENT)) break;

            length = RTM_PAYLOAD(nh);
            for (rtah = RTM_RTA(ndh); RTA_OK(rtah, length);
                rtah = RTA_NEXT(rtah, length)) {

                switch (rtah->rta_type) {
                case NDA_DST:
                    if (ndh->ndm_family == AF_INET) {
                        struct in_addr *inp;
                        inp = (struct in_addr *)RTA_DATA(rtah);
                        inet_ntop(AF_INET, inp, ip, INET_ADDRSTRLEN);
                        i = task->ipv4_index.find(ip);
                        if (i == task->ipv4_index.end())
                            task->ipv4_index[ip] = 1;
                        else
                            task->ipv4_index[ip]++;
                    }
                    else if (ndh->ndm_family == AF_INET6) {
                        struct in6_addr *in6p;
                        in6p = (struct in6_addr *)RTA_DATA(rtah);
                        inet_ntop(AF_INET6, in6p, ip, INET6_ADDRSTRLEN);
                        i = task->ipv6_index.find(ip);
                        if (i == task->ipv6_index.end())
                            task->ipv6_index[ip] = 1;
                        else
                            task->ipv6_index[ip]++;
                    }
                    csLog::Log(csLog::Debug,
                        "%s: NDA_DST: %s", name.c_str(), ip);
                    break;
                case NDA_LLADDR:
                    ::csBinaryToHex((const uint8_t *)RTA_DATA(rtah), ip, 6);
                    i = task->mac_index.find(ip);
                    if (i == task->mac_index.end())
                        task->mac_index[ip] = 1;
                    else
                        task->mac_index[ip]++;
                    csLog::Log(csLog::Debug,
                        "%s: NDA_LLADDR: %s, count: %lu",
                        name.c_str(), ip, task->mac_index[ip]);
                    break;
                }
            }
            
            break;

        case NLMSG_DONE:
            SaveTaskResult(task);
            // Fall through...
        case NLMSG_ERROR:
        case NLMSG_OVERRUN:
            delete task;
            delete event;
            break;

        default:
            csLog::Log(csLog::Warning, "%s: Un-handled netlink type: %d",
                name.c_str(), nh->nlmsg_type);
            break;
        }

        delete [] (uint8_t *)nh;
    }
}

void csPluginAudit::SaveTaskResult(struct csAuditTask *task)
{
    task->sample->users = GetUserCount();
    task->sample->ipv4 = task->sample->ipv6 = task->sample->mac = 0;

    map<string, unsigned long>::iterator index;

    for (index = task->ipv4_index.begin();
        index != task->ipv4_index.end(); index++)
        task->sample->ipv4 += index->second;
    for (index = task->ipv6_index.begin();
        index != task->ipv6_index.end(); index++)
        task->sample->ipv6 += index->second;
    for (index = task->mac_index.begin();
        index != task->mac_index.end(); index++)
        task->sample->mac += index->second;

    map<string, struct csAuditSample *>::iterator i;

    ostringstream json;
    json << "{\"users\":{";
    for (i = sample.begin(); ; ) {
        json << "\"" << i->first << "\":" << i->second->users;
        if (++i != sample.end()) json << ",";
        else break;
    }

    json << "},\"mac\":{";
    for (i = sample.begin(); ; ) {
        json << "\"" << i->first << "\":" << i->second->mac;
        if (++i != sample.end()) json << ",";
        else break;
    }

    json << "},\"ip4\":{";
    for (i = sample.begin(); ; ) {
        json << "\"" << i->first << "\":" << i->second->ipv4;
        if (++i != sample.end()) json << ",";
        else break;
    }

    json << "},\"ip6\":{";
    for (i = sample.begin(); ; ) {
        json << "\"" << i->first << "\":" << i->second->ipv6;
        if (++i != sample.end()) json << ",";
        else break;
    }

    json << "}}";
    csLog::Log(csLog::Debug, "%s: JSON: %s",
        name.c_str(), json.str().c_str());
    json << endl;

    int fd_json;
    fd_json = open(_CSPLUGIN_AUDIT_JSON,
        O_CREAT | O_WRONLY,
        S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd_json >= 0) {

        flock(fd_json, LOCK_EX);
        ftruncate(fd_json, 0);
        lseek(fd_json, 0, SEEK_SET);
        write(fd_json, (const void *)json.str().c_str(), json.str().length());
        flock(fd_json, LOCK_UN);

        close(fd_json);
    }

    map<csTimer *, string>::iterator ti;
    for (ti = timer.begin(); ti != timer.end(); ti++) {
        i = sample.find(ti->second);
        if (i == sample.end()) continue;

        i->second->interval = (unsigned long)ti->first->GetRemaining();
        SetStateVar(i->first,
            sizeof(struct csAuditSample), (uint8_t *)i->second);
    }

    SaveState();
}

void csPluginXmlParser::ParseElementOpen(csXmlTag *tag)
{
    csPluginConf *_conf = static_cast<csPluginConf *>(conf);
    if ((*tag) == "plugin") {
        if (tag->ParamExists("min-uid")) {
            _conf->parent->minuid = atoi(
                tag->GetParamValue("min-uid").c_str());
        }
        if (tag->ParamExists("max-uid")) {
            _conf->parent->maxuid = atoi(
                tag->GetParamValue("max-uid").c_str());
        }
    }
    else if ((*tag) == "sample") {
        if (!stack.size() || (*stack.back()) != "plugin")
            ParseError("unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("name"))
            ParseError("parameter missing: " + tag->GetName());

        struct csAuditSample *sample = NULL;
        string name = tag->GetParamValue("name");

        map<string, struct csAuditSample *>::iterator i;
        i = _conf->parent->sample.find(name);
        if (i != _conf->parent->sample.end())
            ParseError("sample exists: " + name);

        sample = new struct csAuditSample;
        memset(sample, 0, sizeof(struct csAuditSample));
        _conf->parent->sample[name] = sample;

        csTimer *timer = new csTimer(
            _conf->parent->GenerateTimerId(), 0, 0, _conf->parent);
        _conf->parent->timer[timer] = name;
        tag->SetData(static_cast<void *>(timer));
    }
}

void csPluginXmlParser::ParseElementClose(csXmlTag *tag)
{
    csPluginConf *_conf = static_cast<csPluginConf *>(conf);

    if ((*tag) == "sample") {
        if (!stack.size() || (*stack.back()) != "plugin")
            ParseError("unexpected tag: " + tag->GetName());
        string text = tag->GetText();
        if (!text.size())
            ParseError("missing value for tag: " + tag->GetName());

        struct csTimer *timer;
        time_t value = (time_t)atol(text.c_str());

        timer = static_cast<csTimer *>(tag->GetData());
        timer->SetValue(value);
        timer->SetInterval(value);
    }
}

csPluginInit(csPluginAudit);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
