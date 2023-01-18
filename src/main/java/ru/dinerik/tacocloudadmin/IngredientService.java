package ru.dinerik.tacocloudadmin;

public interface IngredientService {

    Iterable<Ingredient> findAll();

    Ingredient addIngredient(Ingredient ingredient);

}