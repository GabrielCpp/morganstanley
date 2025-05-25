def test_read_main(test_client):
    response = test_client.get("/api/v1/applications")
    assert response.status_code == 200
    assert response.json() == [{"username": "Rick"}, {"username": "Morty"}]
