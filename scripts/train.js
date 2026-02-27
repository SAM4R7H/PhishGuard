let tf;
try {
  // Try native bindings first
  tf = require('@tensorflow/tfjs-node');
  console.log("✅ Using @tensorflow/tfjs-node (native bindings)");
} catch (err) {
  // Fallback to pure JS
  tf = require('@tensorflow/tfjs');
  console.log("⚠️ Falling back to @tensorflow/tfjs (pure JS)");
}

const fs = require('fs');
const path = require('path');

// Load dataset
const dataset = JSON.parse(fs.readFileSync('./data/phising.json', 'utf8'));
const texts = dataset.map(item => item.text);
const labels = dataset.map(item => item.label);

// Build vocabulary
const vocab = {};
let index = 1;
texts.forEach(text => {
  text.toLowerCase().split(/\s+/).forEach(word => {
    if (!vocab[word]) vocab[word] = index++;
  });
});

function textToSequence(text) {
  return text.toLowerCase().split(/\s+/).map(word => vocab[word] || 0);
}
function padSequence(seq, maxLen) {
  const pad = Array(maxLen).fill(0);
  seq.slice(0, maxLen).forEach((val, i) => pad[i] = val);
  return pad;
}

const sequences = texts.map(text => textToSequence(text));
const maxLen = 20;
const padded = tf.tensor2d(sequences.map(seq => padSequence(seq, maxLen)));
const ys = tf.tensor2d(labels, [labels.length, 1]);

function createModel(vocabSize, maxLen) {
  const model = tf.sequential({});
  model.add(tf.layers.embedding({ inputDim: vocabSize + 1, outputDim: 50, inputLength: maxLen }));
  model.add(tf.layers.flatten());
  model.add(tf.layers.dense({ units: 64, activation: 'relu' }));
  model.add(tf.layers.dropout({ rate: 0.3 }));
  model.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));

  model.compile({
    optimizer: tf.train.adam(),
    loss: 'binaryCrossentropy',
    metrics: ['accuracy']
  });

  return model;
}

const model = createModel(Object.keys(vocab).length, maxLen);

(async () => {
  await model.fit(padded, ys, {
    epochs: 10,
    batchSize: 2,
    validationSplit: 0.2
  });

  // Save model to disk using a custom save handler so it works
  // with both @tensorflow/tfjs-node and the pure JS fallback.
  const saveDir = path.join(__dirname, '..', 'Models', 'phishingmodel');
  fs.mkdirSync(saveDir, { recursive: true });

  const handler = tf.io.withSaveHandler(async (modelArtifacts) => {
    const modelJson = {
      modelTopology: modelArtifacts.modelTopology,
      format: 'layers-model',
      generatedBy: 'tfjs-custom-save',
      convertedBy: null,
      weightsManifest: [
        { paths: ['weights.bin'], weights: modelArtifacts.weightSpecs || [] }
      ]
    };

    const modelJsonPath = path.join(saveDir, 'model.json');
    const weightsBinPath = path.join(saveDir, 'weights.bin');

    fs.writeFileSync(modelJsonPath, JSON.stringify(modelJson));

    if (modelArtifacts.weightData) {
      const buf = Buffer.from(new Uint8Array(modelArtifacts.weightData));
      fs.writeFileSync(weightsBinPath, buf);
    }

    return {
      modelArtifactsInfo: {
        dateSaved: new Date(),
        modelTopologyType: modelArtifacts.modelTopology ? 'JSON' : 'None',
        modelTopologyBytes: modelArtifacts.modelTopology ? Buffer.byteLength(JSON.stringify(modelArtifacts.modelTopology)) : 0,
        weightDataBytes: modelArtifacts.weightData ? modelArtifacts.weightData.byteLength || modelArtifacts.weightData.length : 0
      }
    };
  });

  await model.save(handler);
  console.log("✅ Model trained and saved to Models/phishingmodel");
})();