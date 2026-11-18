#!/usr/bin/env python3
"""Tiny demo upstream used by the e2e test: a REST API with OpenAPI + a toy GraphQL endpoint."""
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Demo Shop API", version="1.0.0")

PRODUCTS = [
    {"id": 1, "name": "Keyboard", "price": 250000},
    {"id": 2, "name": "Mouse", "price": 150000},
    {"id": 3, "name": "Monitor", "price": 1800000},
]

class ProductIn(BaseModel):
    name: str
    price: int

@app.get("/products", operation_id="list_products", summary="List all products")
def list_products():
    return PRODUCTS

@app.get("/products/{product_id}", operation_id="get_product", summary="Get one product")
def get_product(product_id: int):
    for p in PRODUCTS:
        if p["id"] == product_id:
            return p
    return {"error": "not found"}

@app.post("/products", operation_id="create_product", summary="Create a product")
def create_product(body: ProductIn):
    item = {"id": max(p["id"] for p in PRODUCTS) + 1, "name": body.name, "price": body.price}
    PRODUCTS.append(item)
    return item

@app.post("/graphql")
async def graphql(payload: dict):
    q = payload.get("query", "")
    if "products" in q:
        return {"data": {"products": PRODUCTS}}
    return {"data": {"hello": "world"}}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9001)
