package net.micedre.test;

import java.util.ArrayList;
import java.util.List;
import javax.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.*;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.validation.Validation;

public class RoleAuthentication implements Authenticator, AuthenticatorFactory {

  public static final String PROVIDER_ID = "registration-role-check-action";

  protected static final Logger logger = Logger.getLogger(RoleAuthentication.class);

  @Override
  public String getDisplayType() {
    return "Role from email";
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getHelpText() {
    return "Assigns a role based on the email domain";
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new RoleAuthentication();
  }

  @Override
  public void init(Config.Scope config) {
    // NO-OP
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // NO-OP
  }

  @Override
  public void close() {
    // NO-OP
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
    AuthenticationExecutionModel.Requirement.REQUIRED,
    AuthenticationExecutionModel.Requirement.ALTERNATIVE,
    AuthenticationExecutionModel.Requirement.DISABLED
  };

  private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

  static {
    ProviderConfigProperty property;
    property = new ProviderConfigProperty();
    property.setName("custom-role");
    property.setLabel("Add the custom role");
    property.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
    property.setHelpText("Which custom role to add");

    ProviderConfigProperty mailproperty = new ProviderConfigProperty();
    mailproperty.setName("role-mail");
    mailproperty.setLabel("mail domain");
    mailproperty.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
    mailproperty.setHelpText("For which mail");
    CONFIG_PROPERTIES.add(property);
    CONFIG_PROPERTIES.add(mailproperty);
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_PROPERTIES;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {

    KeycloakSession keycloakSession = context.getSession();
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

    UserModel user = context.getUser();
    String email2 = formData.getFirst(Validation.FIELD_EMAIL);
    if (email2 == null) {
      email2 = user.getEmail();
    }
    AuthenticatorConfigModel mailDomainConfig = context.getAuthenticatorConfig();

    String[] domains =
        mailDomainConfig.getConfig().getOrDefault("role-mail", "example.org").split("##");

    String customRole = mailDomainConfig.getConfig().get("custom-role");

    RoleModel roleModel = keycloakSession.getContext().getRealm().getRole(customRole);
    if (roleModel != null) {
      logger.warn("Role found for : " + customRole);
      for (String domain : domains) {
        if (email2 != null && email2.endsWith(domain)) {
          logger.info("Applying role " + customRole + " to user " + email2);
          user.grantRole(roleModel);
          user.getRealmRoleMappings().add(roleModel);
          user.getRoleMappings().add(roleModel);
          context.success();
          return;
        }
      }
      logger.info("Removing role " + customRole + " for email " + email2);
      user.deleteRoleMapping(roleModel);
    }
    context.success();
  }

  @Override
  public void action(AuthenticationFlowContext authenticationFlowContext) {
    // no-op
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
}
