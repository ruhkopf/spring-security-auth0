package com.auth0.spring.security.auth0;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Filter responsible to intercept the JWT in the HTTP header and attempt an authentication. It delegates the authentication to the authentication manager
 *
 * @author Daniel Teixeira
 */
public class Auth0AuthenticationFilter extends GenericFilterBean {

	@Autowired
	private AuthenticationManager authenticationManager;

	private AuthenticationEntryPoint entryPoint;

	@Override
	public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain) throws IOException, ServletException {

		final HttpServletRequest request = (HttpServletRequest) req;
		final HttpServletResponse response = (HttpServletResponse) res;

		if (request.getMethod().equals("OPTIONS")) {
			// This is CORS request
			chain.doFilter(request, response);
			return;
		}

		final String jwt = getToken(request);

		if (jwt != null) {
			try {

				final Auth0JWTToken token = new Auth0JWTToken(jwt);
				final Authentication authResult = authenticationManager.authenticate(token);
				SecurityContextHolder.getContext().setAuthentication(authResult);

			} catch (final AuthenticationException failed) {
				SecurityContextHolder.clearContext();
				entryPoint.commence(request, response, failed);
				return;
			}
		}

		chain.doFilter(request, response);

	}

	/**
	 * Looks at the authorization bearer and extracts the JWT
	 */
	private String getToken(final HttpServletRequest httpRequest) {
		String token = null;
		final String authorizationHeader = httpRequest.getHeader("authorization");
		if (authorizationHeader == null) {
			// "Unauthorized: No Authorization header was found"
			return null;
		}

		final String[] parts = authorizationHeader.split(" ");
		if (parts.length != 2) {
			// "Unauthorized: Format is Authorization: Bearer [token]"
			return null;

		}

		final String scheme = parts[0];
		final String credentials = parts[1];

		final Pattern pattern = Pattern.compile("^Bearer$", Pattern.CASE_INSENSITIVE);
		if (pattern.matcher(scheme).matches()) {
			token = credentials;
		}
		return token;
	}

	public AuthenticationEntryPoint getEntryPoint() {
		return entryPoint;
	}

	public void setEntryPoint(final AuthenticationEntryPoint entryPoint) {
		this.entryPoint = entryPoint;
	}

}