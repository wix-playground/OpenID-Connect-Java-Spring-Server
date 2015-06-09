/*******************************************************************************
 * Copyright 2015 The MITRE Corporation
 *   and the MIT Kerberos and Internet Trust Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
/**
 *
 */
package org.mitre.jwt.signer.service.impl;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.nimbusds.jose.jwk.JWKSet;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService;
import org.mitre.jwt.encryption.service.impl.DefaultJWTEncryptionAndDecryptionService;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

import java.nio.charset.Charset;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 *
 * Creates a caching map of JOSE signers/validators and encrypters/decryptors
 * keyed on the JWK Set URI. Dynamically loads JWK Sets to create the services.
 *
 * @author jricher
 *
 */
@Service
public class JWKSetCacheService {
	private HttpClient httpClient = HttpClientBuilder.create().useSystemProperties().build();

	/**
	 * Logger for this class
	 */
	private static final Logger logger = LoggerFactory.getLogger(JWKSetCacheService.class);

	// map of jwk set uri -> signing/validation service built on the keys found in that jwk set
	private LoadingCache<String, JWTSigningAndValidationService> validators;

	// map of jwk set uri -> encryption/decryption service built on the keys found in that jwk set
	private LoadingCache<String, JWTEncryptionAndDecryptionService> encrypters;

	public JWKSetCacheService() {
		this.validators = CacheBuilder.newBuilder()
				.expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
				.maximumSize(100)
				.build(new JWKSetVerifierFetcher());
		this.encrypters = CacheBuilder.newBuilder()
				.expireAfterWrite(1, TimeUnit.HOURS) // expires 1 hour after fetch
				.maximumSize(100)
				.build(new JWKSetEncryptorFetcher());
	}

	/**
	 * @param jwksUri
	 * @return
	 * @throws ExecutionException
	 * @see com.google.common.cache.Cache#get(java.lang.Object)
	 */
	public JWTSigningAndValidationService getValidator(String jwksUri) {
		try {
			return validators.get(jwksUri);
		} catch (UncheckedExecutionException ue) {
			logger.warn("Couldn't load JWK Set from " + jwksUri, ue);
			return null;
		} catch (ExecutionException e) {
			logger.warn("Couldn't load JWK Set from " + jwksUri, e);
			return null;
		}
	}

	public JWTEncryptionAndDecryptionService getEncrypter(String jwksUri) {
		try {
			return encrypters.get(jwksUri);
		} catch (UncheckedExecutionException ue) {
			logger.warn("Couldn't load JWK Set from " + jwksUri, ue);
			return null;
		} catch (ExecutionException e) {
			logger.warn("Couldn't load JWK Set from " + jwksUri, e);
			return null;
		}
	}

	JWKSetKeyStore fetch(String key) throws Exception {
		HttpGet method = new HttpGet(key);
		HttpResponse result;
		HttpStatus httpStatus;
		try {
			result = httpClient.execute(method);
			httpStatus = org.springframework.http.HttpStatus.valueOf((result.getStatusLine().getStatusCode()));
		} catch (Exception e) {
			method.abort();
			throw e;
		}

		if (HttpStatus.OK.equals(httpStatus)) {
			JWKSet jwkSet = JWKSet.parse(EntityUtils.toString(result.getEntity()));
			return new JWKSetKeyStore(jwkSet);
		} else {
			byte[] content = null;
			Charset charset = null;
			String reason = result.getStatusLine().getReasonPhrase();
			HttpEntity entity = result.getEntity();
			if (entity != null) {
				charset = ContentType.getOrDefault(entity).getCharset();
				content = EntityUtils.toByteArray(entity);
			}
			method.abort();
			if (HttpStatus.Series.CLIENT_ERROR.equals(httpStatus.series())) {
				throw new HttpClientErrorException(httpStatus, reason, content, charset);
			}
			throw new HttpServerErrorException(httpStatus, reason, content, charset);
		}
	}

	/**
	 * @author jricher
	 *
	 */
	private class JWKSetVerifierFetcher extends CacheLoader<String, JWTSigningAndValidationService> {
		/**
		 * Load the JWK Set and build the appropriate signing service.
		 */
		@Override
		public JWTSigningAndValidationService load(String key) throws Exception {
			return new DefaultJWTSigningAndValidationService(fetch(key));
		}

	}

	/**
	 * @author jricher
	 *
	 */
	private class JWKSetEncryptorFetcher extends CacheLoader<String, JWTEncryptionAndDecryptionService> {
		/* (non-Javadoc)
		 * @see com.google.common.cache.CacheLoader#load(java.lang.Object)
		 */
		@Override
		public JWTEncryptionAndDecryptionService load(String key) throws Exception {
			return new DefaultJWTEncryptionAndDecryptionService(fetch(key));
		}
	}

}
