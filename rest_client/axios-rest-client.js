#!/usr/bin/env node
var axios = require("axios");

class RestClient {
  constructor(baseURL) {
    this.client = axios.create({
      baseURL: baseURL,
      headers: { "Content-Type": "application/json" },
    });
  }

  async get(url, params) {
    try {
      const response = await this.client.get(url, params);
      return response;
    } catch (error) {
      this.axios_error_handler(error);
    }
  }

  async post(url, data, config) {
    try {
      const response = await this.client.post(url, data, config);
      return response;
    } catch (error) {
      this.axios_error_handler(error);
    }
  }

  async put(url, data) {
    try {
      const response = await this.client.put(url, data);
      return response;
    } catch (error) {
      this.axios_error_handler(error);
    }
  }

  async delete(url) {
    try {
      const response = await this.client.delete(url);
      return response;
    } catch (error) {
      this.axios_error_handler(error);
    }
  }

  axios_error_handler(error) {
    if (error.name == "AxiosError") {
      console.log(`AxiosError: ${error.code}. ${error.message}`);
      console.log(`Request: ${error.request._header}`);
      console.log(`Body: ${error.config.data}`);
      throw error;
    } else {
      throw error; // let others bubble up
    }
  }
}

exports.RestClient = RestClient;
