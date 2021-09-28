package com.algaworks.algafood.auth.core;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.stereotype.Component;

import com.algaworks.algafood.auth.domain.model.Usuario;
import com.algaworks.algafood.auth.domain.repository.UsuarioRepository;

@Component
@Primary
public class JpaClientDetailsService implements ClientDetailsService {

	@Autowired
	private UsuarioRepository usuarioRepository;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Override
	public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
		Usuario usuario = usuarioRepository.findByEmail(clientId)
				.orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado com e-mail informado"));
		
		return new ClientDetails() {
			
			@Override
			public boolean isSecretRequired() {
				return true;
			}
			
			@Override
			public boolean isScoped() {
				return false;
			}
			
			@Override
			public boolean isAutoApprove(String scope) {
				return false;
			}
			
			@Override
			public Set<String> getScope() {
				return new HashSet<String>() {{
					this.add("read");
					this.add("write");
				}};
			}
			
			@Override
			public Set<String> getResourceIds() {
				return null;
			}
			
			@Override
			public Set<String> getRegisteredRedirectUri() {
				return new HashSet<String>() {{
					this.add("http://aplicacao-cliente");
				}};
			}
			
			@Override
			public Integer getRefreshTokenValiditySeconds() {
				return 360;
			}
			
			@Override
			public String getClientSecret() {
				return usuario.getSenha();
			}
			
			@Override
			public String getClientId() {
				return usuario.getEmail();
			}
			
			@Override
			public Set<String> getAuthorizedGrantTypes() {
				return new HashSet<String>() {{
					this.add("refresh_token");
					this.add("authorization_code");
					this.add("client_credentials");
					this.add("password");
				}};
			}
			
			@Override
			public Collection<GrantedAuthority> getAuthorities() {
				GrantedAuthority auth = new GrantedAuthority() {
					
					@Override
					public String getAuthority() {
						return "TESTE";
					}
				};
				return Arrays.asList(auth);
			}
			
			@Override
			public Map<String, Object> getAdditionalInformation() {
				return null;
			}
			
			@Override
			public Integer getAccessTokenValiditySeconds() {
				return null;
			}
		};
	}

}