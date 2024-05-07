using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis;
using System.Threading.Tasks;

namespace ProjetoA.Classes
{
    class ComplexidadeCiclomatica
    {
        public static async Task<int> CalcularComplexidadeCiclomatica(SyntaxNode root)
        {
            // Aguarda por 100 milissegundos de forma assíncrona
            var complexityWalker = new ComplexityWalker();
            complexityWalker.Visit(root);
            return await Task.FromResult(complexityWalker.Complexity);
        }

        private class ComplexityWalker : CSharpSyntaxWalker
        {
            public int Complexity { get; private set; }

            public ComplexityWalker() : base(SyntaxWalkerDepth.Trivia)
            {
            }

            // Métodos de visita para estruturas de controle
            public override void VisitIfStatement(IfStatementSyntax node)
            {
                Complexity++;
                base.VisitIfStatement(node);
            }

            public override void VisitSwitchStatement(SwitchStatementSyntax node)
            {
                Complexity++;
                base.VisitSwitchStatement(node);
            }

            public override void VisitConditionalExpression(ConditionalExpressionSyntax node)
            {
                Complexity += 2;
                base.VisitConditionalExpression(node);
            }

            // Adicione outros métodos de visita conforme necessário para contar outras estruturas de controle
            public override void VisitForStatement(ForStatementSyntax node)
            {
                Complexity++;
                base.VisitForStatement(node);
            }
        }
    }
}