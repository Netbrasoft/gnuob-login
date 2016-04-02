/*
 * Copyright 2016 Netbrasoft
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

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

  private static final String[] ALL_VALID_OPTIONS = {"siteQuery"};
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
    final String username = getUsername();
    String site = null;
    Connection conn = null;
    PreparedStatement ps = null;

    try {
      final InitialContext ctx = new InitialContext();
      final DataSource ds = (DataSource) ctx.lookup(dsJndiName);
      conn = ds.getConnection();
      // Get the password
      ps = conn.prepareStatement(siteQuery);
      ps.setString(1, username);
      final ResultSet rs = ps.executeQuery();
      if (!rs.next()) {
        throw new FailedLoginException("No matching username found in Principals");
      }

      site = rs.getString(1);
      site = convertRawPassword(site);
      rs.close();
    } catch (final NamingException ex) {
      throw new LoginException(ex.toString(true));
    } catch (final SQLException ex) {
      log.error("Query failed", ex);
      throw new LoginException(ex.toString());
    } finally {
      if (ps != null) {
        try {
          ps.close();
        } catch (final SQLException e) {
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (final SQLException ex) {
        }
      }
    }
    return site;
  }

  @Override
  public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map<String, ?> sharedState,
      final Map<String, ?> options) {
    addValidOptions(ALL_VALID_OPTIONS);
    super.initialize(subject, callbackHandler, sharedState, options);

    final Object tmp = options.get(SITE_QUERY);
    if (tmp != null) {
      siteQuery = tmp.toString();
    }
  }

  @Override
  public boolean login() throws LoginException {
    if (super.login()) {
      final String[] info = getUsernameAndPassword();
      principal = new GNUOBPrincipal(info[0], info[1], getUsersSite());
      return true;
    }
    return false;
  }
}
