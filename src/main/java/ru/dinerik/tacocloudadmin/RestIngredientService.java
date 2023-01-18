package ru.dinerik.tacocloudadmin;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;


public class RestIngredientService implements IngredientService {

    private final RestTemplate restTemplate;
    public RestIngredientService(String accessToken) {
        this.restTemplate = new RestTemplate();
        if (accessToken != null) {
            this.restTemplate
                    .getInterceptors()
                    .add(getBearerTokenInterceptor(accessToken));
        }
    }

    @Override
    public Iterable<Ingredient> findAll() {
        return Arrays.asList(Objects.requireNonNull(restTemplate.getForObject(
                "http://localhost:8080/api/ingredients",
                Ingredient[].class)));
    }

    @Override
    public Ingredient addIngredient(Ingredient ingredient) {
        return restTemplate.postForObject(
                "http://localhost:8080/api/ingredients",
                ingredient,
                Ingredient.class);
    }

    private ClientHttpRequestInterceptor
    getBearerTokenInterceptor(String accessToken) {

        return (request, bytes, execution) -> {
            request.getHeaders().add("Authorization", "Bearer " + accessToken);
            return execution.execute(request, bytes);
        };
    }
}