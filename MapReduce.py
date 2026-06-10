import pandas as pd
from multiprocessing import Pool
import glob

#MapReduce 
def mapper(file):

    df = pd.read_csv(file)
    resultado = (
        df.groupby("source_category")
        ["event_count"]
        .sum()
        .to_dict()
    )
    return resultado

def reducer(resultados):
    final = {}
    for parcial in resultados:
        for categoria, valor in parcial.items():
            final[categoria] = (
                final.get(categoria, 0)
                + valor
            )
    return final

def run_mapreduce():
    archivos = glob.glob("data/*.csv")
    print(f"Procesando {len(archivos)} fragmentos")
    # Procesamiento paralelo
    #with Pool(processes=5) as pool:
        #maps = pool.map(mapper, archivos)
    maps = list(map(mapper, archivos))

    resultado = reducer(maps)
    ranking = sorted(
      resultado.items(),
     key=lambda x: x[1],
     reverse=True
    )
    return ranking, len(archivos)

if __name__ == "__main__":
    ranking, total_fragmentos = run_mapreduce()
    print(f"\nFragmentos procesados: {total_fragmentos}")
    print("\nRanking de categorías:\n")
    for categoria, total in ranking:
        print(f"{categoria}: {total}")