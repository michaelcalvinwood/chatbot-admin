require ('dotenv').config();
const axios = require('axios');
const { Configuration, OpenAIApi } = require("openai");
const { v4: uuidv4 } = require('uuid');

exports.createCollection = async (host, port, collectionName, size, onDiskPayload = false, distance = 'Cosine') => {
    const request = {
        url: `http://${host}:${port}/collections/${collectionName}`,
        method: 'put',
        headers: {
            'Content-Type': 'application/json;charset=UTF-8',
            "Access-Control-Allow-Origin": "*",
        },
        data: {
            vectors: {
                size,
                distance
            }
        }
    }

    //console.log('onDiskPayload', onDiskPayload);

    if (onDiskPayload) request.data.on_disk_payload = true;
        
    return axios(request);   
}

exports.createOpenAICollection = async (botId, vectorHost, vectorPort, diskBased = false) => {
    return this.createCollection(vectorHost, vectorPort, botId, 1536, diskBased);
}

exports.collectionInfo = async (host, port, collectionName) => {
    const request = {
        url: `http://${host}:${port}/collections/${collectionName}`,
        method: 'get'
    }

    return axios(request);
}

exports.deleteCollection = async (host, port, collectionName) => {
    const request = {
        url: `http://${host}:${port}/collections/${collectionName}`,
        method: 'DELETE'
    }

    return axios(request);
}

exports.addPoint = async (host, port, collectionName, point) => {
    const { id, vector, payload } = point;
    
    const request = {
        url: `http://${host}:${port}/collections/${collectionName}/points`,
        method: 'put',
        headers: {
            'Content-Type': 'application/json;charset=UTF-8',
            "Access-Control-Allow-Origin": "*",
        },
        data: {
            points: [
                {
                    id, vector

                }
            ]
        }
    }

    if (payload) request.data.points[0].payload = payload;

    return axios(request);
}
