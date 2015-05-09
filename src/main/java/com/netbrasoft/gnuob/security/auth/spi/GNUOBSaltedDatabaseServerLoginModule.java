package com.netbrasoft.gnuob.security.auth.spi;

import java.security.Principal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;

import com.netbrasoft.gnuob.security.GNUOBPrincipal;

import de.rtner.security.auth.spi.SaltedDatabaseServerLoginModule;

public class GNUOBSaltedDatabaseServerLoginModule extends SaltedDatabaseServerLoginModule {

   private static final String[] ALL_VALID_OPTIONS = { "siteQuery" };
   private static final String SITE_QUERY = "siteQuery";
   protected String siteQuery = "select Site from Principals where PrincipalID=?";

   private GNUOBPrincipal principal;

   public GNUOBSaltedDatabaseServerLoginModule() {
      siteQuery = "select Site from Principals where PrincipalID=?";
   }

   @Override
   protected Principal getIdentity() {
      return principal != null ? principal : super.getIdentity();
   }

   protected String getUsersSite() throws LoginException {
      String username = getUsername();
      String site = null;
      Connection conn = null;
      PreparedStatement ps = null;

      try {
         InitialContext ctx = new InitialContext();
         DataSource ds = (DataSource) ctx.lookup(dsJndiName);
         conn = ds.getConnection();
         // Get the password
         ps = conn.prepareStatement(siteQuery);
         ps.setString(1, username);
         ResultSet rs = ps.executeQuery();
         if (!rs.next()) {
            throw new FailedLoginException("No matching username found in Principals");
         }

         site = rs.getString(1);
         site = convertRawPassword(site);
         rs.close();
      } catch (NamingException ex) {
         throw new LoginException(ex.toString(true));
      } catch (SQLException ex) {
         log.error("Query failed", ex);
         throw new LoginException(ex.toString());
      } finally {
         if (ps != null) {
            try {
               ps.close();
            } catch (SQLException e) {
            }
         }
         if (conn != null) {
            try {
               conn.close();
            } catch (SQLException ex) {
            }
         }
      }
      return site;
   }

   @Override
   public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
      addValidOptions(ALL_VALID_OPTIONS);
      super.initialize(subject, callbackHandler, sharedState, options);

      Object tmp = options.get(SITE_QUERY);
      if (tmp != null) {
         siteQuery = tmp.toString();
      }
   }

   @Override
   public boolean login() throws LoginException {
      if (super.login()) {
         principal = new GNUOBPrincipal(getUsername(), getUsersPassword(), getUsersSite());
         return true;
      }
      return false;
   }
}
