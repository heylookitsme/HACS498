from sentence_transformers import SentenceTransformer, util
model = SentenceTransformer('distilbert-base-nli-mean-tokens')

sentences = [
    'APTs are extremely dangerous',
    'when i saw an APT i froze in my tracks',
    'this was sponsored by nationwide'
    ]
sentence_embeddings = model.encode(sentences)

for sentence, embedding in zip(sentences, sentence_embeddings):
    print("Sentence:", sentence)
    print("Embedding:", embedding)
    print("")

print(util.pytorch_cos_sim(sentence_embeddings[0], sentence_embeddings[1]))
print(util.pytorch_cos_sim(sentence_embeddings[0], sentence_embeddings[2]))
print(util.pytorch_cos_sim(sentence_embeddings[1], sentence_embeddings[2]))