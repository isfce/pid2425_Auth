package org.isfce.pid.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.isfce.pid.dao.IUserJpaDao;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
	@Bean
	@Order(1)
	SecurityFilterChain asFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		// Active le protocole  OpenID Connect
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

		// Spécifie la page d'authentification pour les utilisateurs
		http.exceptionHandling((e) -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

		return http.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain defaultSecurityFilterChainClient(HttpSecurity http) throws Exception {
		http.formLogin(Customizer.withDefaults());
		
		http.authorizeHttpRequests(c-> c.anyRequest().authenticated());
		return http.build();
	}

	// @formatter:off
	  @Bean
	   RegisteredClientRepository registeredClientRepository(
	          PasswordEncoder passwordEncoder) {
		  //Enregistrement d'une application  client
	      RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
	        .clientId("client")//A changer
	        .clientSecret(passwordEncoder.encode("secret"))
	        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	        // .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
	        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
	        //adapter
	        .redirectUri("https://www.isfce.be/authorized")//Spécifie la ou les redirections possibles en cas de succès
	        .scope("email")
	        .scope("cmd_sandwichs")//scopes demandés par l'application
	        .scope(OidcScopes.OPENID)
	        .scope(OidcScopes.PROFILE)
	        //demande l'acceptation à l'utilisateur pour que l'application accède aux scopes demandés par le client
	        .clientSettings( ClientSettings.builder().requireAuthorizationConsent(true).requireProofKey(true).build()) 
	        .build();
	    return new InMemoryRegisteredClientRepository(registeredClient);
	  }
	  // @formatter:on


/**
 * Ajout des informations au token: email et role
 * @return
 */
	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(IUserJpaDao daoUser) {
		return context -> {
			JwtClaimsSet.Builder claims = context.getClaims();
			assert context.getPrincipal().getAuthorities().size() == 1 : "Problème pas de role";
			String role = context.getPrincipal().getAuthorities().toArray()[0].toString();
			//rajoute le role de l'utilisateur au token
			claims.claim("role", role);
			//rajoute l'email de l'utilisateur au token 
			var oUser=daoUser.findById(context.getPrincipal().getName());
			oUser.ifPresent((m)->claims.claim("email", m.getEmail()));
		};
	}

	/*
	 * Génération des clés RSA
	 */
	@Bean
	JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
		RSAKey rsaKey = generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);// (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	// generate KeyPair
	private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		return keyPairGenerator.generateKeyPair();
	}

	// clés privée et public
	private static RSAKey generateRsa() throws NoSuchAlgorithmException {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
	}

	@Bean
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	/*
	 * 
	 */
	@Bean
	AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
