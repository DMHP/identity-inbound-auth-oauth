package org.wso2.carbon.identity.oauth.endpoint.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.varia.NullAppender;

/**
 * This utility class is used to configure log Appenders and log levels by IdentityBaseTest and
 * PowerMockIdentityBaseTest classes.
 *
 */
public class LogUtil {

    private static final Log log = LogFactory.getLog(LogUtil.class);

    private LogUtil() {
    }

    public static void configureAndAddConsoleAppender() {
        NullAppender appender = new NullAppender();
        LogManager.getRootLogger().addAppender(appender);
    }

    public static void configureLogLevel(String logLevel) {
        Level level = Level.toLevel(logLevel);
        try {
            LogManager.getRootLogger().setLevel(level);
        } catch (Throwable t) {
            //We catch throwable as there is a case where logger level setting fails when old SLF4j library interferes.
            log.error("Could not set the log level to : " + level + ". Probably inconsistent Log4J class is loaded.",
                    t);
        }
    }
}