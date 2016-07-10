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

package br.com.netbrasoft.gnuob.security;

import java.security.Principal;

public class GNUOBPrincipal implements Principal {

  private final String name;
  private final String password;
  // TODO: user can access multiple sites, refactor this to an string of arrays with site names.
  private final String site;

  public GNUOBPrincipal(final String name, final String password, final String site) {
    this.name = name;
    this.password = password;
    this.site = site;
  }

  @Override
  public String getName() {
    return name;
  }

  public String getPassword() {
    return password;
  }

  public String getSite() {
    return site;
  }
}
