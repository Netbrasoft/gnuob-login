package com.netbrasoft.gnuob.security;

import java.security.Principal;

public class GNUOBPrincipal implements Principal {

   private String name;
   private String password;
   // TODO: user can access multiple sites, refactor this to an string of
   // arrays with site names.
   private String site;

   public GNUOBPrincipal(String name, String password, String site) {
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
