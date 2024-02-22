using System.Text.RegularExpressions;

namespace ProjetoA.Classes
{
    internal class Padroes
    {
        // Padrões de Convenções de Nomenclatura:

        public static string PadrãoCamelCaseVariavel => @"\b[a-z][a-zA-Z0-9]*\b";

        public static string PadrãoPascalCaseVariavel => @"\b[A-Z][a-zA-Z0-9]*\b";

        public static string PadrãoCamelCaseMetodo => @"\b[a-z][a-zA-Z0-9]*\b";

        public static string PadrãoPascalCaseMetodo => @"\b[A-Z][a-zA-Z0-9]*\b";

        public static string PadrãoPascalCaseClasse => @"\b[A-Z][a-zA-Z0-9]*\b";

        // Padrões de Espaços em Branco:

        public static string PadrãoEspacosAntesEdepoisDeOperadores => @"\s*([=+\-*/%]|==|!=|<=|>=|<|>)\s*";

        // Padrões de Indentação:

        public static string PadrãoIndentacaoPorEspacos(int quantidadeEspacos) => $@"^[ \t]{{{quantidadeEspacos}}}";

        // Padrões de Comentários:

        public static string PadrãoComentarios => @"\/\/[^\n]*|\/\*.*?\*\/";
    }
}