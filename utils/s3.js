/*
 * Starter code: https://docs.digitalocean.com/products/spaces/reference/s3-sdk-examples/
 */ 

require('dotenv').config();

const { S3, ListObjectsV2Command , ListObjectsCommand, PutObjectCommand, DeleteObjectsCommand } = require("@aws-sdk/client-s3");
const fs = require('fs');
const fse = require('fs-extra');
const fsp = require('fs').promises;
const mime = require('mime-types');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
var path = require('path');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const {S3_ENDPOINT, S3_ENDPOINT_DOMAIN, S3_REGION, S3_KEY, S3_SECRET, S3_BUCKET} = process.env;

exports.client = (S3_ENDPOINT, S3_ENDPOINT_DOMAIN, S3_REGION, S3_KEY, S3_SECRET, S3_BUCKET) => {
  const client = new S3({
      endpoint: S3_ENDPOINT,
      region: S3_REGION,
      credentials: {
          accessKeyId: S3_KEY,
          secretAccessKey: S3_SECRET
      }
  });
  client.meta = {S3_ENDPOINT, S3_ENDPOINT_DOMAIN, S3_REGION, S3_KEY, S3_SECRET, S3_BUCKET}
  return client;
}

exports.emptyS3Directory = async (dir, s3Client) => {
    const Bucket = s3Client.meta.S3_BUCKET;
    const listParams = {
        Bucket,
        Prefix: dir,
        MaxKeys: 1000
    };
  
    let command = new ListObjectsV2Command(listParams);

    const data = await s3Client.send(command);
    
    if (!data.Contents) return;
    if (data.Contents.length === 0) return;

    let deleteParams = {
      Bucket,
      Delete: { Objects: [] }
    };

    data.Contents.forEach(({ Key }) => {
      if (Key !== `${dir}/`) deleteParams.Delete.Objects.push({ Key });
    });


    if (deleteParams.Delete.Objects.length) {
      command = new DeleteObjectsCommand(deleteParams);
  
      await s3Client.send(command);
    
      
    } 

    if (data.IsTruncated) await exports.emptyS3Directory(dir, s3Client);
    else {
      deleteParams = {
        Bucket,
        Delete: {Objects: [{Key: `${dir}/`}]}
      }

      command = new DeleteObjectsCommand(deleteParams);
  
      await s3Client.send(command);
    }


    return true;
}


exports.getPostSignedUrl = async (s3Client, folder, Expires = 3600) => {
    const Bucket = s3Client.meta.S3_BUCKET;
    const params = {
      Bucket,
      Expires,
      Conditions: [
        ['starts-with', '$key', folder]
      ]
    };
    
    s3Client.createPresignedPost(params, (err, data) => {
      if (err) {
        console.error('Presigning post data encountered an error', err);
      } else {
        data.Fields.key = 'path/to/uploads/${filename}';
        console.log('The post data is', data);
      }
    });
  }
exports.contentType = filename => {
    const baseFilename = path.basename(filename);

    const contentType = mime.lookup(baseFilename);

    return contentType ? contentType : 'application/octet-stream';
}

exports.presignedUploadUrl = async (s3Client, Key, expiresIn = 900) => {
    const Bucket = s3Client.meta.S3_BUCKET;
    const ContentType = this.contentType(Key);
    const bucketParams = {Bucket, Key, ContentType};

    console.log(bucketParams);

    try {
      const url = await getSignedUrl(s3Client, new PutObjectCommand({Bucket, Key, ContentType, ACL: 'public-read'}), { expiresIn }); // Adjustable expiration.
      console.log("URL:", url);
      return url;
    } catch (err) {
      console.log("Error", err);
      return false;
    }
}

exports.eraseFolder = async (s3Client, folder) => {
    const Bucket = s3Client.meta.S3_BUCKET;
    const listParams = {
        Bucket,
        Prefix: `${folder}/`
    };

    const listedObjects = await s3Client.send(new ListObjectsV2Command(listParams));

    if (!listedObjects.Contents) return;
    if (listedObjects.Contents.length === 0) return;

    const deleteParams = {
        Bucket,
        Delete: { Objects: [] }
    };

    listedObjects.Contents.forEach(({ Key }) => {
        deleteParams.Delete.Objects.push({ Key });
    });

    await s3Client.send(new DeleteObjectsCommand(deleteParams));

    if (listedObjects.IsTruncated) await this.eraseFolder(folder);
}




exports.uploadFile = async (s3Client, filename, bucketFolder, bucketFileName) => {
    const data = await fsp.readFile(filename);
    let contentType = '';

    const localFileName = path.basename(filename);

    contentType = mime.lookup(localFileName);

    if (!contentType) contentType = 'application/octet-stream';

    const bucketParams = {
        Bucket: process.env.S3_BUCKET,
        Key: `${bucketFolder}/${bucketFileName}`,
        Body: data,
        ACL: 'public-read',
        'Content-Type': contentType
      };
    
      try {
        const data = await s3Client.send(new PutObjectCommand(bucketParams));
        const link = `https://${process.env.S3_BUCKET}.${process.env.S3_ENDPOINT_DOMAIN}/${bucketParams.Key}`;
        return link;
      } catch (err) {
        console.log("Error", err);
        return '';
      }      
};

exports.fileSize = (s3Client, Key) => {
    if (Key.startsWith('/')) Key = Key.substring(1);

    console.log('fileSize', Key);
    return new Promise((resolve, reject) => {
        s3Client.headObject({Bucket: s3Client.meta.S3_BUCKET, Key}, (err, data) => {
            if (err) {
                console.error(err);
                reject(err);
                return;
            }
            //console.log(data);
            resolve(data.ContentLength);
            return;
        })
    })
}

exports.download = async (url, filePath) => {  
  return new Promise(async (resolve, reject) => {
      const writer = fs.createWriteStream(filePath)
  
      let response;

      try {
          response = await axios({
          url,
          method: 'GET',
          responseType: 'stream'
          })
      } catch (e) {
          console.error(e);
          reject(e);
          return false;
      }
      response.data.pipe(writer)

      writer.on('finish', resolve)
      writer.on('error', reject)
  })
}
