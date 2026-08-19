import pyarrow.parquet as pq

TRAIN_PATH = "ml_model/dataset/raw/ember2018/train_ember_2018_v2_features.parquet"

print("Reading Parquet metadata...")

table = pq.ParquetFile(TRAIN_PATH)

print("\nNumber of row groups:", table.num_row_groups)
print("Number of rows:", table.metadata.num_rows)
print("Number of columns:", len(table.schema.names))

print("\nColumns:")
for i, column in enumerate(table.schema.names):
    print(f"{i}: {column}")