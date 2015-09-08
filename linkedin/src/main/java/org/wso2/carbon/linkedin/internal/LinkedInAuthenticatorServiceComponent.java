package org.wso2.carbon.linkedin.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.linkedin.LinkedInOAuth2Authenticator;

import java.util.Hashtable;

/**
 * @scr.component name="identity.application.authenticator.linkedin.component" immediate="true"
 */
public class LinkedInAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(LinkedInAuthenticatorServiceComponent.class);

    protected void activate(ComponentContext ctxt) {
        try {
            LinkedInOAuth2Authenticator linkedInAuthenticator = new LinkedInOAuth2Authenticator();
            Hashtable<String, String> props = new Hashtable<String, String>();

            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    linkedInAuthenticator, props);
            if (log.isDebugEnabled()) {
                log.debug("LinkedIn authenticator is activated");
            }
        } catch (Throwable e) {
            log.fatal("LinkedIn authenticator authenticator ", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("LinkedIn authenticator is deactivated");
        }
    }
}
