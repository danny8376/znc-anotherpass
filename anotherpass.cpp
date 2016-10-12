/*
 * Copyright (C) 2004-2012  See the AUTHORS file for details.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include <znc/znc.h>
#include <znc/User.h>

using std::map;
using std::set;
using std::pair;

class AnotherPassMod : public CModule {
  public:
    MODCONSTRUCTOR(AnotherPassMod) {
        AddHelpCommand();
        AddCommand("Add", static_cast<CModCommand::ModCmdFunc>(
                              &AnotherPassMod::HandleAddCommand),
                   "pass [remainder]");
        AddCommand("Del", static_cast<CModCommand::ModCmdFunc>(
                              &AnotherPassMod::HandleDelCommand),
                   "id");
        AddCommand("Clear", static_cast<CModCommand::ModCmdFunc>(
                              &AnotherPassMod::HandleClearCommand),
                   "", "Remove all previous set passwords");
        AddCommand("List", static_cast<CModCommand::ModCmdFunc>(
                               &AnotherPassMod::HandleListCommand),
                   "", "List your passwords(password hash with remainder)");
    }

    ~AnotherPassMod() override { }

    bool OnBoot() override {
        for (MCString::const_iterator it = BeginNV(); it != EndNV(); ++it) {
            VCString vsKeys;

            if (CZNC::Get().FindUser(it->first) == nullptr) {
                DEBUG("Unknown user in saved data [" + it->first + "]");
                continue;
            }

            it->second.Split(" ", vsKeys, false);
            for (const CString& sKey : vsKeys) {
                m_Passes[it->first].insert(sKey);
            }
        }

        return true;
    }

    void OnPostRehash() override { OnBoot(); }

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        OnBoot();

        return true;
    }

    bool Save() {
        ClearNV(false);
        for (const auto& it : m_Passes) {
            CString sVal;
            for (const CString& sPassHash : it.second) {
                sVal += sPassHash + " ";
            }

            if (!sVal.empty()) SetNV(it.first, sVal, false);
        }

        return SaveRegistry();
    }

    /*
     * Password Format :
     *   Remainder # salt # salted sha256 hash
     */

    bool CheckPass(const CString& sPass, const CString& sPassLine) {
        CString sSalt = sPassLine.Token(1, false, "#");
        CString sHash = sPassLine.Token(2, true, "#");
        return CUtils::SaltedSHA256Hash(sPass, sSalt) == sHash;
    }

    bool AddPass(CUser* pUser, const CString& sPass, const CString& sRemainder) {
        CString sSalt = CUtils::GetSalt();
        CString sHash = CUtils::SaltedSHA256Hash(sPass, sSalt);
        CString sPassLine = sRemainder + "#" + sSalt + "#" + sHash;
        const pair<SCString::const_iterator, bool> pair =
            m_Passes[pUser->GetUserName()].insert(sPassLine);

        if (pair.second) {
            Save();
        }

        return pair.second;
    }

    EModRet OnLoginAttempt(std::shared_ptr<CAuthBase> Auth) override {
        const CString sUser = Auth->GetUsername();
        CUser* pUser = CZNC::Get().FindUser(sUser);

        if (pUser == nullptr) return CONTINUE;

        const CString sPass = Auth->GetPassword();

        if (sPass.empty()) {
            DEBUG("no password given, ignore");
            return CONTINUE;
        }

        MSCString::const_iterator it = m_Passes.find(sUser);
        if (it == m_Passes.end()) {
            DEBUG("No saved passwords for this client");
            return CONTINUE;
        }

        bool passed = false;
        for (const CString& sPassLine : it->second) {
            if (CheckPass(sPass, sPassLine)) {
                passed = true;
                break;
            }
        }

        if (passed) {
            // This client uses a correct another pass for this user, let them in
            DEBUG("Accepted another password auth");
            Auth->AcceptLogin(*pUser);
            return HALT;
        } else {
            DEBUG("another password failed");
            return CONTINUE;
        }
    }

    void HandleAddCommand(const CString& sLine) {
        CString sPass = sLine.Token(1);
        CString sRemainder = sLine.Token(2);

        if (sPass.empty()) {
            PutModule("You did not supply a password.");
        } else {
            if (AddPass(GetUser(), sPass, sRemainder)) {
                PutModule("Password added.");
            } else {
                PutModule("Password is already added.");
            }
        }
    }

    void HandleListCommand(const CString& sLine) {
        CTable Table;

        Table.AddColumn("Id");
        Table.AddColumn("Remainder");
        Table.AddColumn("PassHash");

        MSCString::const_iterator it = m_Passes.find(GetUser()->GetUserName());
        if (it == m_Passes.end()) {
            PutModule("No passwords set for your user");
            return;
        }

        unsigned int id = 1;
        for (const CString& sPassLine : it->second) {
            Table.AddRow();
            Table.SetCell("Id", CString(id++));
            Table.SetCell("Remainder", sPassLine.Token(0, false, "#"));
            Table.SetCell("PassHash", sPassLine.Token(1, true, "#"));
        }

        if (PutModule(Table) == 0) {
            // This double check is necessary, because the
            // set could be empty.
            PutModule("No passwords set for your user");
        }
    }

    void HandleClearCommand(const CString& sLine) {
        MSCString::iterator it = m_Passes.find(GetUser()->GetUserName());

        if (it == m_Passes.end()) {
            PutModule("No passwords set for your user");
            return;
        }

        m_Passes.erase(it);
        PutModule("Cleared");
            
        Save();
    }

    void HandleDelCommand(const CString& sLine) {
        unsigned int id = sLine.Token(1, true).ToUInt();
        MSCString::iterator it = m_Passes.find(GetUser()->GetUserName());

        if (it == m_Passes.end()) {
            PutModule("No passwords set for your user");
            return;
        }

        if (id == 0 || id > it->second.size()) {
            PutModule("Invalid #, check \"list\"");
            return;
        }

        SCString::const_iterator it2 = it->second.begin();
        while (id > 1) {
            ++it2;
            id--;
        }

        it->second.erase(it2);
        if (it->second.size() == 0) m_Passes.erase(it);
        PutModule("Removed");

        Save();
    }

    CString GetWebMenuTitle() override { return "another pass"; }

    bool OnWebRequest(CWebSock& WebSock, const CString& sPageName,
                      CTemplate& Tmpl) override {
        CUser* pUser = WebSock.GetSession()->GetUser();

        if (sPageName == "index") {
            MSCString::const_iterator it = m_Passes.find(pUser->GetUserName());
            if (it != m_Passes.end()) {
                for (const CString& sPassLine : it->second) {
                    CTemplate& row = Tmpl.AddRow("PassLineLoop");
                    row["Line"] = sPassLine;
                    row["Remainder"] = sPassLine.Token(0, false, "#");
                    row["PassHash"] = sPassLine.Token(1, true, "#");
                }
            }

            return true;
        } else if (sPageName == "add") {
            AddPass(pUser, WebSock.GetParam("pass"), WebSock.GetParam("remainder"));
            WebSock.Redirect(GetWebPath());
            return true;
        } else if (sPageName == "delete") {
            MSCString::iterator it = m_Passes.find(pUser->GetUserName());
            if (it != m_Passes.end()) {
                if (it->second.erase(WebSock.GetParam("line", false))) {
                    if (it->second.size() == 0) {
                        m_Passes.erase(it);
                    }

                    Save();
                }
            }

            WebSock.Redirect(GetWebPath());
            return true;
        }

        return false;
    }

  private:
    // Maps user names to a list of passwords
    typedef map<CString, set<CString>> MSCString;
    MSCString m_Passes;
};

/*
template <>
void TModInfo<AnotherPassMod>(CModInfo& Info) {
    Info.SetWikiPage("anotherpass");
}
*/

GLOBALMODULEDEFS(
    AnotherPassMod,
    "Allow users to authenticate via another password")
