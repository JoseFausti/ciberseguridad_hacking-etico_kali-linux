from bs4 import BeautifulSoup
import requests
import pandas as pd

def scrape_news():
    """
    Realiza una solicitud a la página de noticias de Hacker News y extrae los títulos, enlaces y puntuaciones de las noticias.

    Returns:
        tuple: Tres listas conteniendo los títulos, enlaces y puntuaciones de las noticias respectivamente.
    """
    url = "https://news.ycombinator.com/"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    titles = []
    links = []
    scores = []

    # Iteración a través de cada fila de noticia en la página principal
    for item in soup.find_all('tr', class_='athing'):
        title_line = item.find('span', class_='titleline')
        if title_line:
            title = title_line.text
            title_link = title_line.find('a')
            link = title_link['href']
            score = item.find_next_sibling('tr').find('span', class_='score')
            if score:
                score = score.text
            else:
                score = "None"
            titles.append(title)
            links.append(link)
            scores.append(score)
        else:
            print("No se encontró un título para el elemento, se omite.")

    return titles, links, scores

def display_news(titles, links, scores):
    """
    Crea un DataFrame de pandas y lo imprime, mostrando los títulos, enlaces y puntuaciones de las noticias.

    Args:
        titles (list): Lista de títulos de las noticias.
        links (list): Lista de enlaces de las noticias.
        scores (list): Lista de puntuaciones de las noticias.
    """
    df = pd.DataFrame({
        'Title': titles,
        'Link': links,
        'Score': scores
    })

    print(df)

def main():
    """
    Función principal que orquesta la extracción y visualización de las noticias de Hacker News.
    """
    titles, links, scores = scrape_news()
    display_news(titles, links, scores)

if __name__ == "__main__":
    main()