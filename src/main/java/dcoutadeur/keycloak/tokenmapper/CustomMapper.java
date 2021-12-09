package dcoutadeur.keycloak.tokenmapper;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.protocol.ProtocolMapperUtils;
import java.io.*;
import java.util.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;




/**
 * @author David Coutadeur, @dcoutadeur
 */
public class CustomMapper extends AbstractOIDCProtocolMapper
	implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

	public static final String PROVIDER_ID = "oidc-custom-mapper";

	private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

	static final String SEPARATOR = "separator";

	static {
		configProperties.add(new ProviderConfigProperty(SEPARATOR, "separator", "separator between firstname and lastname", ProviderConfigProperty.STRING_TYPE, " "));

		OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
		OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, CustomMapper.class);
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayCategory() {
		return TOKEN_MAPPER_CATEGORY;
	}

	@Override
	public String getDisplayType() {
		return "Custom mapper";
	}

	@Override
	public String getHelpText() {
		return "return firstname + separator + surname";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return configProperties;
	}

	@Override
	protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
		String separator = mappingModel.getConfig().get(SEPARATOR);
		// when separator = (space), the admin interface remove the trailing space
		if(separator == null || separator.equals("")) {
			separator = " ";
		}
		String firstname = "firstName";
		String lastname = "lastName";
		String result;

		UserModel user = userSession.getUser();
		Collection<String> firstnameValue = KeycloakModelUtils.resolveAttribute(user, firstname, false);
		Collection<String> lastnameValue = KeycloakModelUtils.resolveAttribute(user, lastname, false);
		if (firstnameValue == null || lastnameValue == null || firstnameValue.isEmpty() || lastnameValue.isEmpty() ) return;

		result = firstnameValue.iterator().next() + separator + lastnameValue.iterator().next();
		
		OIDCAttributeMapperHelper.mapClaim(token, mappingModel, result);

	}
}
