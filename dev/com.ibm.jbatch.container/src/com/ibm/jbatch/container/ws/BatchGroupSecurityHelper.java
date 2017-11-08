package com.ibm.jbatch.container.ws;

import java.util.List;

import javax.security.auth.Subject;

public interface BatchGroupSecurityHelper {

    /**
     * @return Returns the list of group names
     */
    public List<String> getGroupsForSubject(Subject subject);

}
